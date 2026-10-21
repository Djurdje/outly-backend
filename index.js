// Sentry (#87): vklopljen SAMO ob SENTRY_DSN v okolju (sicer se paket ne naloži); zagon prvi, da ujame tudi napake pri nalaganju modulov.
const sentry = require("./sentry");
sentry.zagon();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");
const net = require("net");
const { Resend } = require("resend");
const { jePrepovedanoIme } = require("./prepovedana_imena");   // filter neprimernih uporabniskih imen (#216 N9)
const { NAJMANJ_LET_RACUN, danesLjubljana, polnaLeta } = require("./starost_racuna");   // najnizja starost racuna 18 let, po ljubljanskem koledarju
const { preveriUrlPolja } = require("./url_polja");   // URL polja kluba/dogodka: samo http(s) (#269)
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
// Sentry: vsak odgovor 500 iz katerekoli poti pride v Sentry (odgovor ostane nespremenjen); brez SENTRY_DSN se ne doda nic.
if (sentry.vklopljen()) app.use(sentry.vmesnik);

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
  // Zetoni naprav (040) ne vplivajo na noben predpomnjen odgovor; aplikacija jih registrira pogosto.
  { metoda: "POST", pot: /^\/me\/devices$/ },
  { metoda: "DELETE", pot: /^\/me\/devices\/[0-9A-Fa-f]+$/ },
  // Prijave zlorabe in bloki (041): pisejo samo reports, user_blocks, friendships in friend_requests; noben predpomnjen odgovor jih ne bere.
  { metoda: "POST", pot: /^\/reports$/ },
  { metoda: "POST", pot: /^\/me\/blocks\/\d+$/ },
  { metoda: "DELETE", pot: /^\/me\/blocks\/\d+$/ },
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

// JIT izklopljen na povezavah glavnega poola, skenPool in omejevalnika (#265; skenPool od 17. 10.). PG16 ima jit=on; plan nad
// jit_above_cost (100 000) prevaja LLVM ob VSAKEM klicu. Izmerjeno lokalno (klub s 50 000 narocili / 100 000 vstopnicami):
// prodaja po dnevih v GET /business/sales (strosek ~195 000) jit=on 27 ms (od tega JIT 15 ms, nova povezava do 107 ms), jit=off 12-14 ms;
// na Renderjevi bazi (0,1 CPU) vec kot 10-krat toliko. Nasih poizvedb (OLTP, kratke) JIT ne pospesi. Zagonski parameter
// `options` ohrani PGOPTIONS okolja (testi). Ima ga tudi zdraviPool (/healthz): baza ali pooler (PgBouncer ipd.), ki zavrne `options`,
// podre VSE poole; /healthz mora biti tedaj 503, da Render tak deploy zavrne in obdrzi staro instanco (pregled #271, S2).
const PG_OPTIONS = [process.env.PGOPTIONS, "-c jit=off"].filter(Boolean).join(" ");
function novPool(max, connectMs, dodatno = {}) {
  const p = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false },
    max,
    options: PG_OPTIONS,
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
// Casovni meji stavkov na skenPool (pregled 17. 10. 2026, S1; I16): migracija ob deployu (ACCESS EXCLUSIVE na tickets/orders do 120 s)
// ali dolga transakcija, ki drzi vrstico vstopnice, sken NE sme zadrzati. NAMEN je lock_timeout: stavek, ki caka na zaklep dlje od
// PG_SKEN_LOCK_TIMEOUT_MS (1 s), Postgres prekine (55P03); pot vrne 503 + Retry-After 5 (odgovoriNaNapako, jeZacasnaNapaka), telefon
// preklopi na sken brez povezave. statement_timeout (57014) je samo varovalo proti obviselemu stavku in NE sme biti ozji od realnega
// hladnega casa stavka na pocasni bazi ali od roka odjemalca (iOS POST /scan 4 s, iOS hitra pot scan-batch 2 s, odjava 5 s):
// privzeto 5000 ms na stavek. scan-list in branje paketa scan-batch (en velik stavek) imata v svoji transakciji visjo mejo
// PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS (privzeto 10000; splet caka scan-list 20 s, iOS 30 s) - glej skenBranje().
// CI 17. 10. 2026: prvi scan-list 5000 vstopnic 3,5 s -> 57014 pri stari meji 2000 ms. Vzrok JIT (PG16 jit=on): plan scan-list ima
// ocenjen strosek ~170 000 na 5000 vstopnic (EXISTS na spori za vsako vrstico), nad jit_above_cost (100 000) -> prevajanje LLVM
// ob VSAKEM klicu (nova povezava se nalozi knjiznico LLVM); 20 000 vstopnic ~660 000 -> tudi inlining + optimizacija.
// Izmerjeno lokalno (4 CPU): 20 000 vstopnic jit=on 431 ms (od tega JIT 389 ms), jit=off 31 ms. Na Renderjevi bazi (0,1 CPU) bi bil
// JIT vec sekund na klic. Zato skenPool povezave tecejo z jit=off (zagonski parameter `options`, ohrani PGOPTIONS okolja).
// 0 = meja izklopljena (velja nastavitev baze). Meje gredo v zagonski paket povezave (node-postgres `lock_timeout`/`statement_timeout`).
const PG_SKEN_LOCK_TIMEOUT_MS = okoljeCelo("PG_SKEN_LOCK_TIMEOUT_MS", 1000, 0, 60000);
const PG_SKEN_STATEMENT_TIMEOUT_MS = okoljeCelo("PG_SKEN_STATEMENT_TIMEOUT_MS", 5000, 0, 60000);
const PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS = okoljeCelo("PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS", 10000, 0, 60000);
// ODJEMALSKI rok poizvedbe skenPool (#265, `query_timeout`): polodprt TCP (baza ali omrezje odgovora nikoli ne poslje in povezave ne
// zapre) ujame samo odjemalec; statement_timeout/lock_timeout tecejo na strezniku in tu ne pomagata. Brez roka bi taka povezava
// visela za vedno, po PG_SKEN_POOL_MAX takih bi sken dobival 503 do restarta (zastoj, /healthz po 60 s). Ob izteku pg poizvedbo
// zavrne z "Query read timeout" (jeNapakaPovezave -> 503 + Retry-After), pool.query povezavo UNICI (release(err)), skenBranje tudi.
// Rok mora biti VECJI od najvecje streznisko meje skenPool (scan-list 10 s prek SET LOCAL), da ne prekine zakonite poizvedbe:
// najmanj ta meja + 2 s (tudi ce je v okolju nastavljeno manj). 0 = izklop. Ob PG_SKEN_STATEMENT_TIMEOUT_MS=0 je to edina meja stavka.
const PG_SKEN_QUERY_TIMEOUT_MS = (() => {
  const v = okoljeCelo("PG_SKEN_QUERY_TIMEOUT_MS", 12000, 0, 120000);
  if (v === 0) return 0;
  return Math.max(v, Math.max(PG_SKEN_STATEMENT_TIMEOUT_MS, PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS) + 2000);
})();
// Streznisko varovalo za polodprt TCP sredi transakcije (pregled #271, S1): query_timeout odjemalca povezavo zavrze, baza pa o tem
// ne izve in seja skenBranje (REPEATABLE READ) ostane `idle in transaction` z AccessShareLock na tickets/orders in starim xmin do TCP
// keepalive (ure) -> migracija z ACCESS EXCLUSIVE ob naslednjem deployu obvisi. idle_in_transaction_session_timeout tako sejo
// zapre na strezniku. Transakcije skenPool med stavki ne mirujejo (BEGIN+SET v enem Query, en stavek, COMMIT), zato 15 s nikoli
// ne prekine zakonitega dela. 0 = izklop.
const PG_SKEN_IDLE_TX_TIMEOUT_MS = okoljeCelo("PG_SKEN_IDLE_TX_TIMEOUT_MS", 15000, 0, 600000);
const skenPool = novPool(PG_SKEN_POOL_MAX, PG_SKEN_CONNECT_TIMEOUT_MS, {
  lock_timeout: PG_SKEN_LOCK_TIMEOUT_MS, statement_timeout: PG_SKEN_STATEMENT_TIMEOUT_MS,
  query_timeout: PG_SKEN_QUERY_TIMEOUT_MS || undefined,
  idle_in_transaction_session_timeout: PG_SKEN_IDLE_TX_TIMEOUT_MS || undefined,
});
console.log(`[skenPool] max ${PG_SKEN_POOL_MAX}, lock_timeout ${PG_SKEN_LOCK_TIMEOUT_MS} ms, statement_timeout ${PG_SKEN_STATEMENT_TIMEOUT_MS} ms, ` +
  `scan-list ${PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS} ms, query_timeout ${PG_SKEN_QUERY_TIMEOUT_MS} ms, idle_in_transaction ${PG_SKEN_IDLE_TX_TIMEOUT_MS} ms, jit=off`);
// Meja seznama nikoli ni nizja od obicajne meje stavka skenPool; 0 = brez SET LOCAL (velja meja povezave).
const SKEN_SEZNAM_MEJA_MS = PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS > 0 && PG_SKEN_STATEMENT_TIMEOUT_MS > 0
  ? Math.max(PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS, PG_SKEN_STATEMENT_TIMEOUT_MS) : PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS;
// Branje za scan-list / scan-batch v kratki transakciji samo za branje z visjo mejo stavka (SET LOCAL velja samo v tej transakciji,
// povezava se vrne v pool z obicajno mejo). lock_timeout ostane 1 s: med migracijo tudi seznam hitro dobi 503.
// REPEATABLE READ: vstopnice in prenosi iz istega posnetka baze.
async function skenBranje(fn) {
  const c = await skenPool.connect();
  let pokvarjen = false;
  try {
    // En preprost Query (ena krozna pot), ne dva.
    await c.query(SKEN_SEZNAM_MEJA_MS > 0 ? `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout = ${SKEN_SEZNAM_MEJA_MS}`
      : "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const r = await fn(c);
    await c.query("COMMIT");
    return r;
  } catch (e) {
    // Baza je odgovorila z napako (SQLSTATE, npr. 57014/55P03): povezava je ziva, ROLLBACK jo pocisti. Brez SQLSTATE (query_timeout,
    // prekinjena povezava): povezava je mrtva ali visi - ROLLBACK bi cakal za obviselo poizvedbo se en rok, zato jo takoj zavrzemo.
    const koda = String((e && e.code) || "");
    if (/^[0-9A-Z]{5}$/.test(koda) && /[0-9]/.test(koda)) await c.query("ROLLBACK").catch(() => { pokvarjen = true; });
    else pokvarjen = true;
    throw e;
  } finally { c.release(pokvarjen); }
}
// Hkratni scan-list (2. krog pregleda #263): scan-list drzi povezavo skenPool do PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS (10 s). Trije
// hkratni veliki seznami po deployu (hladna baza) bi zasedli vse PG_SKEN_POOL_MAX (3) povezave in sken na vratih bi po
// PG_SKEN_CONNECT_TIMEOUT_MS dobil 503. Zato v tem procesu tece najvec max(1, PG_SKEN_POOL_MAX - 1) scan-list hkrati; ostali TAKOJ
// 503 + Retry-After (brez vrste: telefon obdrzi star seznam in poskusi kasneje), vsaj ena povezava ostane skenu.
const SKEN_SEZNAM_HKRATI = Math.max(1, PG_SKEN_POOL_MAX - 1);
let skenSeznamovTece = 0;
// GET /healthz (Renderjev Health Check Path) ima LASTEN pool z eno povezavo: ob navali nakupov je glavni pool zaseden, zdravje
// v njegovi vrsti ne dobi povezave v roku, vrne 503 in Render instanco ponovno zazene - ravno med navalom (issue #117).
// Ena povezava je dovolj (en SELECT 1 naenkrat; ostali zahtevki za zdravje cakajo kratek rok) in steje proti max_connections
// baze (glej .env.example). Kratka roka: baza, ki ne odgovori v ~2 s, je za zdravje res nedosegljiva.
// `query_timeout` je ODJEMALSKI rok: ce povezava obvisi (polodprt TCP, baza je ne zapre), `statement_timeout` na strezniku
// nikoli ne steče; ob izteku pg poizvedbo zavrne, pool.query pa povezavo UNICI (release(err)), zato naslednji klic dobi novo.
// Brez tega bi edina povezava obvisela za vedno in /healthz bi ostal 503 tudi po okrevanju (pregled PR #127).
// Isti zagonski `options` kot ostali pooli (PG_OPTIONS): /healthz tako preveri tudi, da baza parametre povezave SPREJME.
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
// Drzalec dovoljenja in povezave nakupa (#274): enkratno sprostitev (povezava + dovoljenje) lahko sprozi nakupStripeSeja takoj po COMMIT-u,
// `finally` poti jo ponovi brez ucinka (dvojni c.release() bi vrgel, dvojni nakupIzstopi() bi pokvaril stevec dovoljenj).
function nakupDrzalec(c) {
  const d = { c, drzi: true, sprosti(err) { if (!d.drzi) return; d.drzi = false; try { c.release(err); } finally { nakupIzstopi(); } } };
  return d;
}
// Klic Stripa (checkout.sessions.create, rok 15 s, do 3 poskusi) NE sme drzati dovoljenja nakupa ne povezave z bazo: pocasen Stripe bi sicer
// ustavil nakupe vseh klubov, tudi brezplacne in testne (#274). Ima lasten, sirsi semafor: naval ne odpre stotin hkratnih klicev (Stripova
// omejitev hitrosti, odprte vticnice). Cakalci cakajo v pomnilniku brez povezave; po STRIPE_CAKANJE_MS dobi kupec 503, narocilo pa `failed`.
const STRIPE_VZPOREDNO = okoljeCelo("STRIPE_VZPOREDNO", 24, 1, 500);
const STRIPE_CAKANJE_MS = okoljeCelo("STRIPE_CAKANJE_MS", 20000, 10, 120000);
const stripeVrsta = []; let stripeAktivnih = 0;
function stripeVstopi() {
  if (stripeAktivnih < STRIPE_VZPOREDNO) { stripeAktivnih++; return Promise.resolve(true); }
  return new Promise((resolve) => {
    const cak = { dodeli: () => { clearTimeout(cak.timer); resolve(true); } };
    cak.timer = setTimeout(() => { const i = stripeVrsta.indexOf(cak); if (i >= 0) stripeVrsta.splice(i, 1); resolve(false); }, STRIPE_CAKANJE_MS);
    stripeVrsta.push(cak);
  });
}
function stripeIzstopi() {
  const naslednji = stripeVrsta.shift();
  if (naslednji) naslednji.dodeli(); else stripeAktivnih--;
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
// lock_timeout / statement_timeout / mrtva zanka (40P01: Postgres je transakcijo prekinil in vrnil nazaj; ponovitev je varna, pregled #316 M10)
function napakaZasedenosti(err) { return !!err && (err.code === "55P03" || err.code === "57014" || err.code === "40P01"); }
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
  options: PG_OPTIONS,   // jit=off (#265)
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

// poUporabniku: stej na prijavljenega uporabnika (za requireAuth), ne na IP - npr. podpis za Cloudinary (S2, 17. 10. 2026), kjer en racun
// z mnogo IP-ji (mobilno omrezje) ne sme obiti meje in vec ljudi za istim NAT-om (klub, wifi) ne sme deliti ene meje.
function omeji({ kljuc, najvec, oknoSekund, priNapaki = "zapri", poUporabniku = false }) {
  return async (req, res, next) => {
    const kdo = poUporabniku && req.user && req.user.userId ? `uporabnik:${req.user.userId}` : req.ip;   // "uporabnik:N" ni IP: predponaIp ga pusti
    const id = kljucOmejitve(kljuc, najvec, oknoSekund, kdo);
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
// PATCH /me: 3–20 znakov, črke/številke/podčrtaj, in ne na seznamu prepovedanih imen
// (prepovedana_imena.js). Tu ne moremo vrniti 400 (vrstica nastane med overitvijo seje,
// uporabnik bi ostal brez računa), zato prepovedano ime iz metapodatkov tiho nadomesti »user«
// (NE del e-naslova: ta bi postal javno ime, ki si ga uporabnik ni izbral); uporabnik ga zamenja
// prek PATCH /me. Manjkajoče ali neveljavno ime: del e-naslova; isti filter velja tudi zanj
// (»admin@…« ne postane »admin«), sicer »user«.
function predlogImena(p) {
  const meta = p.user_metadata || {};
  const zeljeno = typeof meta.username === "string" ? meta.username.trim() : "";
  if (/^[a-zA-Z0-9_]{3,20}$/.test(zeljeno)) {
    if (!jePrepovedanoIme(zeljeno)) return zeljeno;
    return "user";   // izbrano ime je prepovedano: del e-naslova bi postal javno ime brez obvestila
  }
  const osnova = String(p.email).split("@")[0].replace(/[^a-zA-Z0-9_]/g, "").slice(0, 16);
  return (osnova.length >= 3 && !jePrepovedanoIme(osnova) ? osnova : "user") ;
}

// Povezava po e-naslovu in nov račun: DVE plasti (issue #222, invarianta I35).
// `user_metadata` v žetonu lahko prijavljen uporabnik spreminja sam (updateUser({ data })), zato
// `user_metadata.email_verified` ni dokaz lastništva naslova; ostane samo hitri filter.
//
// PLAST 1 (varovalo, ZAVRNITEV / fail closed): ob izklopljenem »Confirm email« (mailer_autoconfirm) GoTrue
// ob registraciji SAM nastavi email_confirmed_at in user_metadata.email_verified (signup → user.Confirm()), zato
// bi plast 2 v ravno tem scenariju rekla »potrjen«. Zato backend bere javni GET /auth/v1/settings (predpomnilnik
// 60 s) in ob `mailer_autoconfirm === true` ali `external.anonymous_users === true` NE poveže in NE ustvari
// vrstice: 503 + Retry-After (ne 401, I10) in glasen console.error. Izpad / rok / odgovor ≠ 200 / slab JSON → 503.
// PLAST 2: GET /auth/v1/user z uporabnikovim žetonom: email_confirmed_at != null, enak e-naslov (lower) in
// enak id kot sub (manjkajoč id = zavrnitev). Ujame napačno zaupanje metapodatkom pri vklopljenem »Confirm email«.
// Obe plasti samo za uid brez lokalne vrstice (prvi klic računa); vroča pot (vrstica po uid) brez klica navzven.
// Izpad / rok / kakršenkoli odgovor ≠ 200 ali slabo telo (tudi 401/403/404: ni ločljivo od napačnega ključa ali
// izbrisanega računa) → napaka z `jwks = true` → 503 + Retry-After, nikoli 401 (I10).
// Nepotrjen ali neujemajoč naslov → "email_unverified" (403), kot prej.
const POTRDITEV_ROK_MS = 5000;
const potrditevVLetu = new Map();      // uid|email -> Promise (vzporedni prvi klici istega računa = en klic na Supabase)
const potrditevZavrnjena = new Map();  // uid|email -> { potek, tip } (kratek negativni predpomnilnik: isti žeton ne sproža klica ob vsakem zahtevku)
const POTRDITEV_ZAVRNJENA_MS = 10 * 1000;   // nepotrjen / neujemajoč naslov → 403
const POTRDITEV_IZPAD_MS = 5 * 1000;        // izpad /user (4xx, 5xx, rok) → 503
const POTRDITEV_USPELA_MS = 5 * 1000;
const NASTAVITVE_ROK_MS = 5000;
const NASTAVITVE_OSVEZI_MS = 60 * 1000;
const nastavitveSupabase = { vrednost: null, nalozeno: 0, vLetu: null, zadnjiAlarm: 0 };

function napakaPotrditve(sporocilo) {
  const n = new Error("supabase /user: " + sporocilo); n.jwks = true; return n;
}
function napakaNastavitev(sporocilo) {
  const n = new Error("supabase /settings: " + sporocilo); n.jwks = true; return n;
}

async function naloziNastavitveSupabase() {
  let telo;
  try {
    const r = await fetch(SUPABASE_ISS + "/settings", { headers: { apikey: SUPABASE_KEY }, signal: AbortSignal.timeout(NASTAVITVE_ROK_MS) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    telo = await r.json();
  } catch (e) { throw napakaNastavitev(e && e.message); }
  if (!telo || typeof telo !== "object" || typeof telo.mailer_autoconfirm !== "boolean"
      || !telo.external || typeof telo.external !== "object" || typeof telo.external.anonymous_users !== "boolean") {
    throw napakaNastavitev("nepricakovan odgovor");
  }
  return { autoconfirm: telo.mailer_autoconfirm, anonimni: telo.external.anonymous_users };
}

// Vrže (503), če so nastavitve nedosegljive ali nevarne. Uspeh se predpomni 60 s, neuspeh nikoli.
async function preveriNastavitveSupabase() {
  const zdaj = Date.now();
  if (!nastavitveSupabase.vrednost || zdaj - nastavitveSupabase.nalozeno >= NASTAVITVE_OSVEZI_MS) {
    if (!nastavitveSupabase.vLetu) {
      nastavitveSupabase.vLetu = naloziNastavitveSupabase()
        .then((v) => { nastavitveSupabase.vrednost = v; nastavitveSupabase.nalozeno = Date.now(); })
        .finally(() => { nastavitveSupabase.vLetu = null; });
    }
    await nastavitveSupabase.vLetu;
  }
  const v = nastavitveSupabase.vrednost;
  if (v.autoconfirm || v.anonimni) {
    // Glasen, a najvec en zapis na 60 s (zavrnitev je lahko na vsak zahtevek novega uid; dnevnik/Sentry ne smeta poplaviti).
    if (zdaj - nastavitveSupabase.zadnjiAlarm >= NASTAVITVE_OSVEZI_MS) {
      nastavitveSupabase.zadnjiAlarm = zdaj;
      console.error("[auth] POZOR: Supabase mailer_autoconfirm/anonymous_users vklopljen — nove povezave in novi racuni zavrnjeni (503) dokler »Confirm email« ni spet vklopljen"
        + ` (mailer_autoconfirm=${v.autoconfirm}, anonymous_users=${v.anonimni})`);
    }
    const n = new Error("supabase nastavitve: autoconfirm/anonymous"); n.jwks = true; throw n;
  }
}

async function potrditevEmailaPriViru(token, uid, email) {
  let r, telo;
  try {
    r = await fetch(SUPABASE_ISS + "/user", {
      headers: { authorization: "Bearer " + token, apikey: SUPABASE_KEY },
      signal: AbortSignal.timeout(POTRDITEV_ROK_MS),
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    telo = await r.json();
  } catch (e) { throw napakaPotrditve(e && e.message); }
  if (!telo || typeof telo !== "object") throw napakaPotrditve("odgovor");
  // Samo email_confirmed_at: confirmed_at je generiran LEAST(email_confirmed_at, phone_confirmed_at) in bi pri računu
  // s potrjenim telefonom potrdil naslov, ki ni potrjen.
  const emailVirni = typeof telo.email === "string" ? telo.email.trim().toLowerCase() : "";
  const uidVirni = typeof telo.id === "string" ? telo.id.toLowerCase() : "";
  if (!telo.email_confirmed_at || emailVirni !== email || uidVirni !== uid) throw new Error("email_unverified");
}

function potrdiEmailPriViru(token, uid, email) {
  const k = uid + "|" + email;
  const zdaj = Date.now();
  const zavrnjen = potrditevZavrnjena.get(k);
  if (zavrnjen && zavrnjen.potek > zdaj) {
    return Promise.reject(zavrnjen.tip === "izpad" ? napakaPotrditve("predpomnjen izpad") : new Error("email_unverified"));
  }
  let p = potrditevVLetu.get(k);
  if (!p) {
    p = potrditevEmailaPriViru(token, uid, email)
      .catch((e) => {
        const tip = e && e.message === "email_unverified" ? "zavrnjen" : (e && e.jwks ? "izpad" : null);
        if (tip) {
          if (potrditevZavrnjena.size > 5000) potrditevZavrnjena.clear();
          potrditevZavrnjena.set(k, { potek: Date.now() + (tip === "izpad" ? POTRDITEV_IZPAD_MS : POTRDITEV_ZAVRNJENA_MS), tip });
        }
        throw e;
      })
      .then(
        (v) => { setTimeout(() => potrditevVLetu.delete(k), POTRDITEV_USPELA_MS).unref(); return v; },   // uspeh velja še nekaj sekund: pozni vzporedni prvi klici ne sprožijo novega klica
        (e) => { potrditevVLetu.delete(k); throw e; }
      );
    potrditevVLetu.set(k, p);
  }
  return p;
}

// Lokalna vrstica za Supabasov račun:
//   1. po supabase_uid (vroča pot, brez klica navzven),
//   2. po e-naslovu (obstoječi račun iz časov lastne prijave → poveže se),
//   3. sicer nova vrstica (email_verified = true, brez gesla).
// Koraka 2 in 3 (in rezervna pot ob konfliktu e-naslova) samo, ko sta uspeli obe plasti (preveriNastavitveSupabase +
// potrdiEmailPriViru); `token` je surovi Supabasov žeton klicatelja.
async function uporabnikIzSupabase(p, db = pool, token = null) {
  const uid = p.sub.toLowerCase();
  const email = String(p.email).trim().toLowerCase();

  if (izbrisaniSub.has(uid)) throw new Error("izbrisan");

  const r1 = await db.query(`SELECT ${POLJA_SEJE} FROM users WHERE supabase_uid=$1`, [uid]);
  if (r1.rows.length) return r1.rows[0];

  // Povezava po e-naslovu in nov račun samo s POTRJENIM e-naslovom. Hitri filter: user_metadata.email_verified
  // (ga zapiše Supabase ob potrditvi, a ga lahko uporabnik ponaredi → ni dokaz); dokaz je potrditev pri viru.
  if (!(p.user_metadata && p.user_metadata.email_verified === true)) throw new Error("email_unverified");
  if (typeof token !== "string" || !token) throw new Error("email_unverified");   // brez žetona ni preverbe → ni pisanja
  await preveriNastavitveSupabase();                 // plast 1: ob izklopljenem »Confirm email« ZAVRNI (fail closed)
  await potrdiEmailPriViru(token, uid, email);       // plast 2: potrditev pri viru

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
          // isti lastnik naslova se je pri Supabase registriral znova. Do sem pridemo samo po
          // potrdiEmailPriViru (zgoraj): brez potrditve pri viru se tuj uid NE prepiše (I35).
          // Najprej poglej, ali ni vrstice za TA uid že naredil vzporedni prvi klic (tekma): takrat ni kaj prepisovati.
          const r4a = await db.query(`SELECT ${POLJA_SEJE} FROM users WHERE supabase_uid=$1`, [uid]);
          if (r4a.rows.length) return r4a.rows[0];
          const r4 = await db.query(
            `UPDATE users SET supabase_uid=$1 WHERE email=$2 RETURNING ${POLJA_SEJE}`, [uid, email]
          );
          if (r4.rows.length) { console.warn("[auth] supabase_uid prepisan po potrditvi e-naslova pri viru, user", r4.rows[0].id); return r4.rows[0]; }
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
  const u = await uporabnikIzSupabase(p, db, token);
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
// 'manager', 'doorman' ali 'bartender'. Vsak uporabnik ima največ en klub.
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
    `SELECT c.id AS club_id, c.name AS club_name, c.logo_url AS club_logo_url, 'owner' AS role, 0 AS vrstni, c.is_organizer
       FROM clubs c WHERE c.owner_user_id = $1
     UNION ALL
     SELECT c.id, c.name, c.logo_url, m.role, 1, c.is_organizer
       FROM club_members m JOIN clubs c ON c.id = m.club_id WHERE m.user_id = $1
     ORDER BY 5, 1`, [userId]
  );
  return r.rows.map(x => ({ club_id: x.club_id, club_name: x.club_name, club_logo_url: x.club_logo_url || "", role: x.role, is_organizer: x.is_organizer }));
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
// Vratar (doorman) sme SAMO skenirati in gledati vstopnice dogodka. Natakar (bartender, 038) sme SAMO strezbo VIP miz
// (GET/PUT .../table-service) in nikoli poti s podatki kupcev (vstopnice, skener, VIP rezervacije; I27).
const INT4_MAX = 2147483647;
const { jeVOknuSkena, jeDogodekMinil, SKEN_OKNO_PRED_MS } = require("./sken_okno");   // casovno okno skena (I25), varovalo odpovedi (I42)
const { jeZacasnaNapaka, odgovoriNaNapako } = require("./napaka_povezave");   // 503 samo za zacasne napake baze (povezava, 55P03), ostalo 500
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
      // Tudi 55P03 (lock_timeout skenPool med migracijo, S1 17. 10. 2026) je zacasna.
      if (jeZacasnaNapaka(e)) {
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

// ---------------------------
// POTISNA OBVESTILA (APNs; migracija 040, invarianta I29, issue #183)
// ---------------------------
// Push je POLEG zvonca, nikoli namesto njega (vrstica v zvoncu nastane kot doslej). Poslje se PO commitu, brez await (`void posljiPush…`):
// izpad ali pocasnost APNs nikoli ne podre ali upocasni zahtevka, najmanj skena na vratih (I16). Brez APNS_KEY_ID/APNS_TEAM_ID/APNS_KEY_P8
// je push izklopljen (no-op). Protokol, JWT in omejitve so v push_apns.js; pogodba z iOS (polja, `outly.type`): DECISIONS 10. 10. 2026.
const { ustvariApns, sestaviObvestilo, ZETON_VZOREC } = require("./push_apns");
const apns = ustvariApns();
// Strezba starejsa od tega (sken brez povezave, poslan pozno) ne sprozi pusha: »miza je pripravljena« po pol ure ni vec novica (seznam strezbe ostane).
const PUSH_STREZBA_SVEZE_MIN = 30;
const NAPRAV_NA_UPORABNIKA = 10;   // najvec zetonov naprav na uporabnika (POST /me/devices pobrise najstarejse)

const PUSH = {
  prejetaVstopnica: (vstopnicaId, posiljatelj) => sestaviObvestilo({ tip: "ticket_received", id: vstopnicaId, naslov: "New ticket",
    kljuc: "%@ sent you a ticket", argumenti: [posiljatelj || "Someone"] }),
  dogodekKluba: (dogodekId, klub, naslov) => sestaviObvestilo({ tip: "club_event", id: dogodekId, naslov: "New event",
    kljuc: "%@ posted a new event: %@", argumenti: [klub, naslov] }),
  vabiloGuestLista: (vstopnicaId, gostitelj) => sestaviObvestilo({ tip: "guest_list_invite", id: vstopnicaId, naslov: "Guest list",
    kljuc: "%@ added you to their guest list", argumenti: [gostitelj || "Someone"] }),
  // Brez kupca/gosta (I27): samo oznaka mize. Ne dostavljeno v pol ure ni vec aktualno: apns-expiration 1 h.
  strezba: (strezbaId, oznakaMize) => sestaviObvestilo({ tip: "table_service", id: strezbaId, naslov: "VIP table",
    kljuc: "VIP table %@ is ready to be served", argumenti: [oznakaMize], velja: 3600 }),
};

async function zetoniUporabnikov(ids) {
  const urejeni = [...new Set((ids || []).filter((x) => Number.isInteger(x) && x > 0))];
  if (!urejeni.length) return [];
  const r = await pool.query("SELECT token FROM device_tokens WHERE user_id = ANY($1::int[]) AND invalid_at IS NULL", [urejeni]);
  return r.rows.map((x) => x.token);
}
// Poslje eno obvestilo na zetone in neveljavne (410 / Unregistered / BadDeviceToken) oznaci invalid_at. DeviceTokenNotForTopic je napaka nastavitve (topic): ne oznaci.
// `last_seen_at <= zacetek`: zeton, ki ga je aplikacija med posiljanjem znova registrirala, ostane veljaven.
// Varovalo: ce je v enem posiljanju vsaj PUSH_MNOZICNO_MIN zetonov in vec kot polovica zavrnjena z BadDeviceToken, je skoraj gotovo narobe okolje
// (npr. sandbox zetoni proti produkciji), ne zetoni: BadDeviceToken NE oznacimo in zapisemo alarm. 410 / Unregistered (reinstalacija, odjava) oznacimo VEDNO:
// to so dokazano mrtvi zetoni in sicer bi zastareli zetoni trajno blokirali ciscenje. ALARM najvec enkrat na minuto.
const PUSH_MNOZICNO_MIN = 10;
let pushAlarmZadnji = 0;
// Vrne zetone, ki so bili oznaceni kot neveljavni (klicatelj z vec obvestili jih izloci iz naslednjih).
async function posljiNaZetone(zetoni, obvestilo, tip) {
  if (!zetoni.length) return [];
  const zacetek = new Date();
  const rez = await apns.posljiVsem(zetoni, obvestilo);
  const zavrnjenih = rez.filter((r) => r.neveljaven).length;
  let neveljavni = rez.filter((r) => r.neveljaven).map((r) => r.zeton);
  const slabih = rez.filter((r) => r.neveljaven && r.razlog === "BadDeviceToken");
  if (rez.length >= PUSH_MNOZICNO_MIN && slabih.length * 2 > rez.length) {
    const slabiZetoni = new Set(slabih.map((r) => r.zeton));
    neveljavni = neveljavni.filter((z) => !slabiZetoni.has(z));   // 410 / Unregistered ostanejo oznaceni
    if (Date.now() - pushAlarmZadnji >= 60000) {
      pushAlarmZadnji = Date.now();
      console.error(`[push] ALARM: ${slabih.length} od ${rez.length} zetonov zavrnjenih z BadDeviceToken v enem posiljanju (${tip}), teh ne oznacim: verjetno napacno okolje/kljuc (sandbox zetoni proti produkciji? APNS_TOPIC? APNS_KEY_*?)`);
    }
  }
  if (neveljavni.length) {
    await pool.query("UPDATE device_tokens SET invalid_at = NOW() WHERE token = ANY($1::text[]) AND invalid_at IS NULL AND last_seen_at <= $2", [neveljavni, zacetek]);
  }
  console.log(`[push] ${tip}: ${rez.length} naprav, poslano ${rez.filter((r) => r.ok).length}, neveljavnih ${neveljavni.length}, zavrnjenih ${zavrnjenih}, napak ${rez.filter((r) => !r.ok && !r.neveljaven).length}`);
  return neveljavni;
}
// Klic MORA biti `void posljiPush(...)` PO commitu: nikoli ne vrze (vse napake v dnevnik), zato ne podre klicatelja.
async function posljiPush(uporabnikiIds, obvestilo, tip) {
  if (!apns.vklopljen) return;
  try { await posljiNaZetone(await zetoniUporabnikov(uporabnikiIds), obvestilo, tip); }
  catch (e) { console.error(`[push] ${tip} ni uspel:`, e && e.message); }
}
// Objava dogodka sledilcem: samo tisti, ki so pravkar dobili vrstico v zvoncu (ponovna objava ne poslje znova); skriti klub ne objavlja.
async function pushObjavaDogodka(eventId, uporabnikiIds) {
  if (!apns.vklopljen || !uporabnikiIds.length) return;
  try {
    const e = await pool.query(
      `SELECT e.title, c.name FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1 AND e.status = 'published' AND NOT c.hidden`, [eventId]);
    if (!e.rows.length) { console.log("[push] club_event: preskoceno (dogodek ni objavljen ali je klub skrit)"); return; }
    await posljiNaZetone(await zetoniUporabnikov(uporabnikiIds), PUSH.dogodekKluba(eventId, e.rows[0].name, e.rows[0].title), "club_event");
  } catch (e) { console.error("[push] club_event ni uspel:", e && e.message); }
}
// Strezba VIP mize: lastnik + manager + bartender kluba (vloge iz baze ob posiljanju, I5), NE vratar; vsebina brez kupca (I27).
async function pushStrezba(klubId, strezbaIds) {
  if (!apns.vklopljen || !strezbaIds.length) return;
  try {
    // Samo strezba, ki bi bila vidna v zvoncu (isti casovni pogoj kot stevec in seznam: STREZBA_ZVONEC_CAS) in je sveza.
    const s = await pool.query(
      `SELECT ts.id, ts.table_label ${STREZBA_ZVONEC_IZ}
        WHERE ts.id = ANY($1::int[]) AND ts.club_id = $2 AND ts.delivered_at IS NULL AND ${STREZBA_ZVONEC_CAS}
          AND ts.scanned_at > NOW() - make_interval(mins => $3::int) ORDER BY ts.id`,
      [strezbaIds, klubId, PUSH_STREZBA_SVEZE_MIN]);
    if (!s.rows.length) { console.log("[push] table_service: preskoceno (strezba ni vidna v zvoncu ali je zastarela)"); return; }
    const p = await pool.query(
      `SELECT owner_user_id AS user_id FROM clubs WHERE id = $1 AND owner_user_id IS NOT NULL
       UNION SELECT user_id FROM club_members WHERE club_id = $1 AND role IN ('manager', 'bartender')`, [klubId]);
    let zetoni = await zetoniUporabnikov(p.rows.map((x) => x.user_id));
    for (const x of s.rows) {
      const neveljavni = new Set(await posljiNaZetone(zetoni, PUSH.strezba(x.id, x.table_label), "table_service"));
      if (neveljavni.size) zetoni = zetoni.filter((z) => !neveljavni.has(z));   // naslednja strezba teh zetonov ne dobi
    }
  } catch (e) { console.error("[push] table_service ni uspel:", e && e.message); }
}

// POST /me/devices { token, platform } — registracija zetona naprave (aplikacija po dovoljenju za obvestila). Idempotentno; isti zeton na drugem racunu
// (odjava in prijava na isti napravi) se prepise na trenutnega, invalid_at -> NULL, last_seen_at = zdaj. Neveljaven zeton 400.
// Omejevalnik je na IP: aplikacija naj klice ob spremembi zetona ali najvec enkrat na dan, ne ob vsakem zagonu (omrezja z NAT delijo IP).
app.post("/me/devices", requireAuth, omeji({ kljuc: "naprave", najvec: 60, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  try {
    const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
    if (typeof b.token !== "string" || !ZETON_VZOREC.test(b.token)) return res.status(400).json({ error: "invalid_token", message: "token must be a hex device token (64-200 characters)." });
    const platforma = b.platform === undefined ? "ios" : b.platform;
    if (platforma !== "ios") return res.status(400).json({ error: "invalid_platform", message: "platform must be \"ios\"." });
    // Najvec NAPRAV_NA_UPORABNIKA zetonov: v ISTI transakciji kot vpis se izbrisejo najstarejsi (po last_seen_at) cez mejo, da en racun ne nabira zetonov
    // (vsak zeton je en zahtevek APNs na vsak push).
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      // Sočasne registracije ISTEGA uporabnika se vrstijo (brez zastoja 40P01 in brez preseganja meje): advisory lock na uporabnika do konca transakcije.
      await c.query("SELECT pg_advisory_xact_lock(hashtext('dev:' || $1::text))", [req.user.userId]);
      await c.query(
        `INSERT INTO device_tokens (user_id, token, platform) VALUES ($1, $2, $3)
         ON CONFLICT (token) DO UPDATE SET user_id = EXCLUDED.user_id, platform = EXCLUDED.platform, last_seen_at = NOW(), invalid_at = NULL`,
        [req.user.userId, b.token.toLowerCase(), platforma]);
      await c.query(
        `DELETE FROM device_tokens WHERE user_id = $1 AND id NOT IN
           (SELECT id FROM device_tokens WHERE user_id = $1 ORDER BY last_seen_at DESC, id DESC LIMIT $2)`, [req.user.userId, NAPRAV_NA_UPORABNIKA]);
      await c.query("COMMIT");
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
    finally { c.release(); }
    return res.status(200).json({ ok: true });
  } catch (e) { return odgovoriNaNapako(res, e, "POST /me/devices"); }
});

// DELETE /me/devices/:token — odjava naprave (aplikacija ob odjavi). Brise SAMO zeton trenutnega uporabnika; tuj ali neobstojec zeton je tudi 204
// (ne razkrijemo, ali obstaja). Neveljaven zapis zetona 400.
app.delete("/me/devices/:token", requireAuth, omeji({ kljuc: "naprave", najvec: 60, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  try {
    if (!ZETON_VZOREC.test(req.params.token)) return res.status(400).json({ error: "invalid_token", message: "token must be a hex device token (64-200 characters)." });
    await pool.query("DELETE FROM device_tokens WHERE token = $1 AND user_id = $2", [req.params.token.toLowerCase(), req.user.userId]);
    return res.status(204).end();
  } catch (e) { return odgovoriNaNapako(res, e, "DELETE /me/devices/:token"); }
});

// POST /help/feedback { article, helpful } — »Was this helpful?« pod clankom pomoci v aplikaciji (migracija 049). Clanki so staticni v aplikaciji, zato strezniku
// seznam clankov NI znan (aplikacija doda clanek brez deploya): preveri se samo oblika id-ja. En glas na uporabnika na clanek: ponovni glas prepise prejsnjega
// (helpful + updated_at). Odgovor 204. Omejevalnik je na IP kot pri /me/devices (omrezja z NAT delijo IP, zato 120/h, ne 60).
const POMOC_CLANEK_VZOREC = /^[a-z0-9-]{1,40}$/;
app.post("/help/feedback", requireAuth, omeji({ kljuc: "pomoc-odziv", najvec: 120, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  try {
    const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
    if (typeof b.article !== "string" || !POMOC_CLANEK_VZOREC.test(b.article)) return res.status(400).json({ error: "invalid_article", message: "article must be 1-40 characters: lowercase letters, digits and hyphens." });
    if (typeof b.helpful !== "boolean") return res.status(400).json({ error: "invalid_helpful", message: "helpful must be true or false." });
    await pool.query(
      `INSERT INTO help_feedback (user_id, article, helpful) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, article) DO UPDATE SET helpful = EXCLUDED.helpful, updated_at = now()`,
      [req.user.userId, b.article, b.helpful]);
    return res.status(204).end();
  } catch (e) { return odgovoriNaNapako(res, e, "POST /help/feedback"); }
});

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

// GET /healthz/sken (#265): ali povezave skenPool (sken na vratih) delujejo: ima svoje zagonske meje (lock/statement/idle timeout),
// ki jih /healthz (zdraviPool) ne preveri, in svoj zastoj/izcrpanje povezav. Namenjena Nadzoru produkcije (preverbo dodaja PR #272;
// dokler ni mergan, je pot samo za rocno preverbo po deployu). Brez avtentikacije, brez podatkov v odgovoru ({ ok }). Ni Renderjev
// Health Check (ta ostane /healthz).
// Zloraba ne sme izcrpati skenPool: v procesu tece najvec ENA preverba (SELECT 1) naenkrat, rezultat velja 1 s (vsi klici v tem
// casu dobijo zadnji rezultat brez baze). Obvisela preverba drzi najvec eno povezavo, dokler je ne sprosti query_timeout skenPool;
// medtem nova preverba ne zacne (klici po 3 s dobijo 503). Torej: najvec 1 povezava skenPool in najvec ~1 SELECT 1 na sekundo.
const SKEN_ZDRAVJE_VELJA_MS = 1000, SKEN_ZDRAVJE_ROK_MS = 3000;
let skenZdravjeZadnje = null;    // { ok, cas }
let skenZdravjePoizvedba = null; // tekoca preverba (Promise<boolean>), dokler se poizvedba res ne konca
function preveriSkenPool() {
  if (skenZdravjePoizvedba) return skenZdravjePoizvedba;
  skenZdravjePoizvedba = skenPool.query("SELECT 1").then(() => true, (e) => {
    console.error("[zdravje] skenPool ni dosegljiv ->", 503, e && e.message);
    return false;
  }).then((ok) => { skenZdravjeZadnje = { ok, cas: Date.now() }; skenZdravjePoizvedba = null; return ok; });
  return skenZdravjePoizvedba;
}
app.get("/healthz/sken", async (req, res) => {
  res.set("Cache-Control", "no-store");
  let ok;
  if (skenZdravjeZadnje && Date.now() - skenZdravjeZadnje.cas < SKEN_ZDRAVJE_VELJA_MS) ok = skenZdravjeZadnje.ok;
  else {
    let casovnik;
    ok = await Promise.race([preveriSkenPool(), new Promise((r) => { casovnik = setTimeout(() => r(false), SKEN_ZDRAVJE_ROK_MS); })]);
    clearTimeout(casovnik);
  }
  res.status(ok ? 200 : 503).json({ ok });
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

// Strezba VIP miz za natakarja (migracija 038, I27): nedostavljene strezbe v klubih, kjer je uporabnik lastnik, manager ali bartender,
// za dogodke, ki TECEJO (od 2 h pred zacetkom do konca; konec = end_at, sicer start + 8 h kot KONEC_DOGODKA), brez odpovedanih.
// Skupno stevcu v GET /me (pending_table_service) in seznamu GET /me/table-service ($1 = id uporabnika), da se ne razideta. Vratar strezbe ne vidi.
const STREZBA_ZVONEC_IZ = `FROM table_service ts
       JOIN events e ON e.id = ts.event_id
       JOIN clubs c ON c.id = ts.club_id`;
// Casovni pogoj »strezba je v zvoncu« je skupen zvoncu (stevec, seznam) in pushu (pushStrezba): push se ne poslje za strezbo, ki je v zvoncu ne bi bilo.
const STREZBA_ZVONEC_CAS = `e.status <> 'cancelled'
        AND NOW() >= e.start_at - INTERVAL '2 hours' AND NOW() < COALESCE(e.end_at, e.start_at + INTERVAL '8 hours')`;
const STREZBA_ZVONEC_KJE = `WHERE ts.delivered_at IS NULL AND ${STREZBA_ZVONEC_CAS}
        AND (c.owner_user_id = $1 OR EXISTS (SELECT 1 FROM club_members m WHERE m.club_id = ts.club_id AND m.user_id = $1 AND m.role IN ('manager', 'bartender')))`;

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
    // Nedostavljene strezbe VIP miz (migracija 038): znacka natakarja/managerja/lastnika; za ostale 0.
    const ps = await pool.query(`SELECT COUNT(*)::int AS n ${STREZBA_ZVONEC_IZ} ${STREZBA_ZVONEC_KJE}`, [req.user.userId]);
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
      pending_table_service: ps.rows[0] ? ps.rows[0].n : 0,
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

// Zanri iz baze (npr. podedovani od kluba): normaliziraj kot preveriZanre, neznane in ne-nize samo izpusti (brez 400).
function ociscenoZanre(seznam) {
  if (!Array.isArray(seznam)) return [];
  return [...new Set(seznam.filter(g => typeof g === "string").map(g => g.trim().toLowerCase()))].filter(g => ZANRI.includes(g));
}

// Zanri iz vhoda na VSEH poteh, ki jih pisejo (PATCH /me, POST/PATCH klub, POST/PATCH dogodek): seznam nizov,
// normaliziran (trim, lowercase, brez podvojenih), vsak mora biti v ZANRI. Brez tega bi poljuben niz (npr. <img onerror>)
// prisel v bazo in od tam v admin panel in v odjemalce (stored XSS, pregled #238). Vrne seznam ali null, ce je
// 400 ze poslan (neznan zanr: { error: "unknown_genres", message, unknown, allowed }).
function preveriZanre(vhod, res) {
  if (!Array.isArray(vhod)) { res.status(400).send("genres must be an array."); return null; }
  if (vhod.length > ZANRI.length) { res.status(400).send("Too many genres."); return null; }
  if (vhod.some(g => typeof g !== "string")) { res.status(400).send("genres must be an array of strings."); return null; }
  const izbrani = [...new Set(vhod.map(g => g.trim().toLowerCase()))];
  const neznani = izbrani.filter(g => !ZANRI.includes(g));
  if (neznani.length > 0) {
    res.status(400).json({ error: "unknown_genres", message: "Unknown genres.", unknown: neznani.slice(0, 20).map(g => g.slice(0, 60)), allowed: ZANRI });
    return null;
  }
  return izbrani;
}

// Najnizja starost za uporabniski racun (NAJMANJ_LET_RACUN = 18) in stetje starosti po ljubljanskem koledarju: starost_racuna.js
// (Martin, 19. 10. 2026, seja menedzerja, vprasanje »Starostna meja«: »18+ in racun od 18«; prej 15 po ZVOP-2, 8. clen).
// Meja je SAMO tam. NI isto kot min_age dogodka in STAROST_PAKET_PIJACE (to sta starosti za nakup).

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
      // Filter neprimernih imen (#216 N9): samo za NOVO ime. Obstoječe ime (iz časov pred filtrom) se sme ponovno
      // shraniti, tudi če bi ga filter danes zavrnil; branje iz baze je samo na redki poti zadetka.
      if (jePrepovedanoIme(ime)) {
        const sedanje = await pool.query("SELECT 1 FROM users WHERE id=$1 AND LOWER(username)=LOWER($2)", [req.user.userId, ime]);
        if (sedanje.rows.length === 0) {
          return res.status(400).json({ error: "username_not_allowed", message: "Username not allowed. Choose a different name." });
        }
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
        // Resnicen koledarski datum (2000-02-31 bi JS premaknil v marec, Postgres pa ga zavrne -> 500).
        if (Number.isNaN(dat.getTime()) || gostDatumRojstva(String(d)) === null) return res.status(400).send("Invalid dateOfBirth.");
        // Vse po ljubljanskem koledarju (isti »danes« kot pri meji 18): datum rojstva »danes« ni v prihodnosti.
        const danes = danesLjubljana();
        if (String(d) > danes) return res.status(400).send("dateOfBirth cannot be in the future.");
        const leta = polnaLeta(String(d), danes);
        if (leta > 120) return res.status(400).send("dateOfBirth is not plausible.");
        // Najnizja starost racuna (NAJMANJ_LET_RACUN, od 19. 10. 2026 18). Aplikacija to preveri ze pred posiljanjem; streznik je zadnja obramba.
        // Meja velja SAMO ob nastavitvi ali spremembi datuma rojstva: obstojec racun pod mejo (vpisan, ko je veljalo 15) ostane nedotaknjen
        // in sme urejati ime, zanre ipd.; isti datum, ki je ze v bazi, ni sprememba (odjemalec ob shranjevanju profila pogosto poslje vsa polja).
        if (leta < NAJMANJ_LET_RACUN) {
          const nespremenjen = await pool.query("SELECT 1 FROM users WHERE id=$1 AND date_of_birth = $2::date", [req.user.userId, String(d)]);
          if (nespremenjen.rows.length === 0) return res.status(400).send(`You must be at least ${NAJMANJ_LET_RACUN} years old.`);
        }
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
      const izbrani = preveriZanre(b.genres, res);
      if (!izbrani) return;
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

      // 1c. #276 S4: cakajoca (neplacana) narocila se prekliceta, SAMO v tej transakciji. Brez tega bi anonimizacija (user_id -> NULL) pustila odprt Checkout:
      //     kupec bi ga lahko se placal, zakljuci() bi naredil vstopnice brez imetnika, brez potrdila, vracila bi ne bilo (denar bi sel klubu). Preklic sprozi
      //     sprosti_zalogo; ce placilo kljub temu prispe (tekma, odlozeno placilo), zakljuci() vidi `cancelled` in kupcu vrne vse (`inactive_order`, I37).
      //     UPDATE zaklene vrstice: hkratni zakljuci() pocaka in vidi `cancelled`; ze placano ostane placano (ne ujema WHERE).
      const preklicana = (await odjemalec.query(
        `UPDATE orders SET status = 'cancelled', cancelled_at = NOW()
          WHERE user_id = $1 AND status = 'pending' RETURNING id, event_id, stripe_checkout_session_id`, [req.user.userId])).rows;

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
      // Po COMMIT-u: odprte Checkout seje zapremo pri Stripu (kupec ne more vec placati). Napaka ni usodna (seja je ze `complete`/potekla, Stripe nedosegljiv):
      // racun je izbrisan, narocilo je `cancelled`, morebitno placilo pa vrne zakljuci() (varovalo). Ne cakamo odgovora uporabniku. Sandbox seja ob zivem kljucu: Stripe je ne pozna.
      for (const n of preklicana) razprodanoPozabi("v:" + n.event_id);
      const sStripe = preklicana.length ? placilaStripe.stripe() : null;
      if (sStripe) {
        for (const n of preklicana) {
          if (!n.stripe_checkout_session_id || (placilaStripe.jeLive() && /^cs_test_/.test(n.stripe_checkout_session_id))) continue;
          Promise.resolve().then(() => sStripe.checkout.sessions.expire(n.stripe_checkout_session_id))
            .catch((e) => console.log(`[me] izbris racuna: seja ${n.stripe_checkout_session_id} ni zaprta (${e && e.message}); ce bo placana, vrne zakljuci()`));
        }
      }
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
// aplikacija ga ne bere; lastnika pove `my_role` / `GET /me`, admin ga dobi iz adminStolpciKluba().
// Stolpci, ki smejo ven javno. NAMENOMA ni "SELECT *": migracija 002 je
// klubom dodala stripe_account_id, ki z zvezdico ni bil viden nikomur v
// pregledu, javno pa bi ga vrnil vsak klic /clubs. Vsak nov stolpec je
// treba tu dodati zavestno.
const JAVNI_STOLPCI_KLUBA = `id, name, logo_url, banner_url, description,
  contact_email, contact_phone, instagram, website, address, city, country,
  lat, lng, min_age, genres, created_at, bar_prices, gallery_urls, video_url,
  is_organizer, is_official, is_demo,
  (SELECT COUNT(*)::int FROM club_follows cf WHERE cf.club_id = clubs.id) AS followers_count`;

// Demo klub (migracija 050, Martin 13. 10. 2026): izmisljen klub za predstavitev. DODANO javno polje `is_demo` (klubi, dogodki = is_demo PRODAJALCA events.club_id,
// iskanje, zemljevid); nakup vstopnic/VIP miz za njegove dogodke je 409 `demo_club` (spodaj), razen vloge admin (testiranje toka; odlocitev agenta, DECISIONS).
// Nastavi ga SAMO admin (PATCH /admin/api/clubs/:id). Invarianta I41.
const NAPAKA_DEMO_KLUB = { error: "demo_club", message: "This is a demo club. Tickets can't be bought." };
// `e` = vrstica dogodka z `is_demo` kluba-prodajalca (events.club_id; pri gostovanem dogodku organizator, ne prizorisce). `vloga` = req.user.role ali undefined (gost).
// Klic mora biti PRED rezervacijo zaloge/mize, vpisom naroclila in klicem Stripa (brez stranskih ucinkov). Vrne telo 409 ali null.
function napakaDemoKluba(e, vloga) {
  return e.is_demo === true && vloga !== "admin" ? NAPAKA_DEMO_KLUB : null;
}

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

// Podatki prodajalca (migracija 043, #94, #101, invarianta I33): kupec mora pred nakupom izvedeti, kdo je prodajalec (ZVPot-1 18/1-2, 130/1-1).
// Prodajalec je VEDNO klub `events.club_id` (pri gostovanem dogodku organizator, ne prizorisce). Surova polja vidi samo lastnik
// (GET /business/clubs/me) in admin; javnost dobi objekt `seller` (spodaj), ki ne vsebuje nicesar, kar ni ze javno ali zakonsko obvezno.
const STOLPCI_PRODAJALCA = "legal_name, legal_address, registration_number, tax_number, vat_payer";
const PRODAJALEC_NAJVEC = { legal_name: 200, legal_address: 300, registration_number: 20, tax_number: 20 };
// Stolpec -> ime v zahtevku (camelCase; sprejmemo tudi snake_case). Pri PATCH /business/clubs/me jih sme spremeniti samo lastnik (403 owner_only).
const PRODAJALEC_POLJA = [["legal_name", "legalName"], ["legal_address", "legalAddress"], ["registration_number", "registrationNumber"], ["tax_number", "taxNumber"], ["vat_payer", "vatPayer"]];
const jeNepraznNiz = (s) => typeof s === "string" && s.trim() !== "";
// Ali so podatki prodajalca popolni: firma, sedez, maticna, davcna NISO prazni (surova polja, ne nadomestki) IN je DDV status vpisan IN je vsaj en kontakt.
function prodajalecPopoln(k) {
  return jeNepraznNiz(k.legal_name) && jeNepraznNiz(k.legal_address) && jeNepraznNiz(k.registration_number) && jeNepraznNiz(k.tax_number)
    && (k.vat_payer === true || k.vat_payer === false) && (jeNepraznNiz(k.contact_phone) || jeNepraznNiz(k.contact_email));
}
// Placljiv nakup v ZIVEM nacinu zahteva popolne podatke prodajalca (I34; ZVPot-1 18/1 2. tc.; Martin 12. 10. 2026): kupec mora pred nakupom
// poznati identiteto in naslov prodajalca. Velja samo, ko nakup RES gre skozi zivi Stripe (`nacin === "stripe"`, sk_live_) in je znesek > 0;
// brezplacno (0 EUR), sandbox (sk_test_) in testni nacin (klub brez Stripa, brez kljuca, TEST_PLACILA) se ne spremenijo. `e` je vrstica dogodka
// z legal_*, registration_number, tax_number, vat_payer, contact_phone, contact_email kluba (events.club_id = prodajalec). Klic mora biti PRED
// rezervacijo zaloge/mize, vpisom naroclila in klicem Stripa (brez stranskih ucinkov; idempotencni kljuc se ne zapise). Vrne telo 409 ali null.
const NAPAKA_PRODAJALEC_NEPOPOLN = { error: "seller_incomplete", message: "This organizer has not completed seller details yet. Purchase is not available." };
// EN SAM pogoj I34 (#220): uporabljata ga nakup (`napakaProdajalca` -> 409) in javni `payment_mode` ("unavailable"), da se nikoli ne razideta:
// kupec ne sme videti gumba za nakup, ki ga bo strezniku zavrnil. `k` ima polja prodajalca (vrstica kluba ali `seller_raw`).
function prodajalecZavraNakup(k, nacin, skupajCents) {
  return nacin === "stripe" && skupajCents > 0 && placilaStripe.jeLive() && !prodajalecPopoln(k);
}
function napakaProdajalca(e, nacin, skupajCents) {
  return prodajalecZavraNakup(e, nacin, skupajCents) ? NAPAKA_PRODAJALEC_NEPOPOLN : null;
}
// EN SAM pogoj I49 (Martin 18. 10. 2026): klub BREZ dokoncanega Stripa v TEKOCEM nacinu (`nacin === "klub"`: sk_live_ in klub brez Connecta ali z racunom iz sandboxa, I36)
// zavrne samo PLACLJIV nakup (denar brez povezanega racuna ne sme nikamor); znesek natanko 0 gre mimo Stripa (`placanoTakoj`), zato je kupljiv. Fail closed:
// vse, kar ni natanko 0 (tudi NaN), je zavrnjeno. Uporabljajo ga vse tri nakupne poti (`napakaKlubaBrezStripa`) in javni `payment_mode` (`javniNacinProdajalca`).
function klubBrezStripaZavraNakup(nacin, skupajCents) {
  return nacin === "klub" && skupajCents !== 0;
}
const NAPAKA_KLUB_BREZ_STRIPA = "This club does not accept online payments yet.";
// Kot `napakaProdajalca`: vrne besedilo 409 ali null. Klic PRED rezervacijo zaloge/mize, vpisom naroclila in idempotentnim kljucem (ROLLBACK brez stranskih ucinkov).
function napakaKlubaBrezStripa(nacin, skupajCents) {
  return klubBrezStripaZavraNakup(nacin, skupajCents) ? NAPAKA_KLUB_BREZ_STRIPA : null;
}
// Razlog, zakaj je `payment_mode` kluba "unavailable" (samo GET /business/sales, lastnik in manager; #220): "stripe_not_ready" (live, klub brez dokoncanega Stripa -> nacin "klub"),
// "payments_not_configured" (Stripe kljuc brez webhook skrivnosti -> "nastavitve", 503), "seller_incomplete" (live, klub s Stripom, nepopolni podatki prodajalca). Sicer null.
function razlogNerazpolozljivosti(nacin, k, najvecCents, brezplacno) {
  if (javniNacinProdajalca(nacin, k, najvecCents, brezplacno) !== "unavailable") return null;
  if (nacin === "klub") return "stripe_not_ready";
  if (nacin === "nastavitve") return "payments_not_configured";
  return "seller_incomplete";
}
// `payment_mode` za odjemalce (#149, #220): kot `javniNacin`, le da ob pogoju I34 vrne "unavailable" namesto "stripe". `najvecCents` = najvecji znesek,
// ki ga kupec lahko placa (> 0 = placljivo); `brezplacno` = obstaja kupljiva ponudba za 0 EUR (ta gre mimo Stripa in I34, zato ostane kupljiva).
function javniNacinProdajalca(nacin, k, najvecCents, brezplacno) {
  // I49: klub brez Stripa: ponudba za 0 EUR je kupljiva ("stripe": brez Checkouta, kot pri klubu s Stripom), placljiva ne ("unavailable"); isti pogoj kot nakup.
  // Brez kupljive ponudbe (npr. dogodek brez vstopnic) ostane "unavailable" kot doslej (znesek 0 bi bil napacno »brezplacen«, zato Math.max(.., 1)).
  if (nacin === "klub") return klubBrezStripaZavraNakup(nacin, brezplacno ? 0 : Math.max(najvecCents, 1)) ? "unavailable" : "stripe";
  if (nacin === "stripe" && !brezplacno && prodajalecZavraNakup(k, nacin, najvecCents)) return "unavailable";
  return placilaStripe.javniNacin(nacin);
}
// Javni objekt `seller` iz vrstice kluba (name, legal_*, registration_number, tax_number, vat_payer, address, city, contact_phone, contact_email).
// Ime/naslov imata nadomestek (clubs.name; "address, city"), zato je `seller` uporaben tudi, ko klub podatkov se ni vpisal (`complete: false`).
function prodajalec(k) {
  const niz = (s) => (typeof s === "string" ? s.trim() : "");
  const naslov = [niz(k.address), niz(k.city)].filter(Boolean).join(", ");
  return {
    name: niz(k.legal_name) || niz(k.name),
    address: niz(k.legal_address) || naslov,
    registration_number: niz(k.registration_number),
    tax_number: niz(k.tax_number),
    vat_payer: k.vat_payer === true || k.vat_payer === false ? k.vat_payer : null,
    phone: niz(k.contact_phone),
    email: niz(k.contact_email),
    complete: prodajalecPopoln(k),
    // I50: DODANO polje, prisotno (true) samo, ko je prodajalec platforma (uradni profil Outly, NEXT DIMENSIONS): odjemalec ne sme pisati »Outly je samo posrednik«.
    // Pri navadnem klubu polja ni (oblika `seller` ostane 8 polj). Pri narocilu odloca oznaka narocila (gostNarociloOdgovor), pri klubu/dogodku zastavica kluba.
    ...(k.is_official === true || k.is_platform === true ? { is_platform: true } : {}),
  };
}
// Surova polja za `prodajalec()` kot JSON (pomozni stolpec `seller_raw`, ga koda odstrani). `a` je vzdevek tabele clubs.
const sqlProdajalecSurov = (a) => `jsonb_build_object('name', ${a}.name, 'legal_name', ${a}.legal_name, 'legal_address', ${a}.legal_address,
  'registration_number', ${a}.registration_number, 'tax_number', ${a}.tax_number, 'vat_payer', ${a}.vat_payer,
  'address', ${a}.address, 'city', ${a}.city, 'contact_phone', ${a}.contact_phone, 'contact_email', ${a}.contact_email, 'is_official', ${a}.is_official)`;
// Vrstice dogodka: `seller` iz pomoznega stolpca `seller_raw` (SQL_PRODAJALEC_DOGODKA); odvisen je samo od kluba, zato sme v javni predpomnilnik (I17).
const SQL_PRODAJALEC_DOGODKA = `(SELECT ${sqlProdajalecSurov("cp")} FROM clubs cp WHERE cp.id = events.club_id) AS seller_raw`;
function dodajProdajalca(vrstice) {
  for (const r of vrstice) {
    r.seller = r.seller_raw ? prodajalec(r.seller_raw) : null;
    delete r.seller_raw;
  }
  return vrstice;
}
// Lastnik/admin: surova polja ostanejo, zraven pride `seller_complete` (isto pravilo kot `seller.complete`).
function dodajSellerComplete(vrstica) {
  if (vrstica) vrstica.seller_complete = prodajalecPopoln(vrstica);
  return vrstica;
}
// Vrednost polja iz telesa: camelCase ali snake_case; `null` je veljavna vrednost (zato ne `??`). undefined = polja ni.
function poljeTelesa(b, camel, snake) {
  return b[camel] !== undefined ? b[camel] : b[snake];
}
// Preveri polja prodajalca iz telesa. Vrne { polja } (samo poslana; nizi trim, null -> "", vat_payer true|false|null) ali { napaka }.
function preveriPodatkeProdajalca(b) {
  const polja = {};
  for (const [stolpec, camel] of PRODAJALEC_POLJA) {
    const v = poljeTelesa(b, camel, stolpec);
    if (v === undefined) continue;
    if (stolpec === "vat_payer") {
      if (v !== null && typeof v !== "boolean") return { napaka: "vatPayer must be true, false or null." };
      polja.vat_payer = v;
      continue;
    }
    if (v !== null && typeof v !== "string") return { napaka: `${camel} must be a string.` };
    const t = v === null ? "" : v.trim();
    if (t.length > PRODAJALEC_NAJVEC[stolpec]) return { napaka: `${camel}: at most ${PRODAJALEC_NAJVEC[stolpec]} characters.` };
    polja[stolpec] = t;
  }
  return { polja };
}

// I36 (#227): Stripe Connect racun kluba je lahko iz SANDBOXA (acct_ testnega Connecta) ali iz ZIVEGA nacina; zivi kljuc sandbox racuna ne pozna
// (Checkout s testnim `transfer_data.destination` pade, `accounts.retrieve` in `accountLinks` tudi). `clubs.stripe_account_livemode` (migracija 046):
// TRUE = zivi, FALSE = sandbox, NULL = neznano = SANDBOX (vsi zapisi pred 046 so nastali v sandboxu: produkcija do preklopa tece na sk_test_).
// Racun velja za »povezan v tem nacinu« samo, ce se nacin racuna ujema z kljucem (`jeLive()`); sicer klub NI pripravljen in se `stripe_charges_enabled`/
// `stripe_payouts_enabled` ne upostevata (nacin "klub" = 409 stripe_not_ready / payment_mode "unavailable"), `stripeRacunKluba` pa naredi NOV racun.
// To je EDINO mesto za SQL (literal `TRUE`/`FALSE` iz `jeLive()` ob klicu, ne ob nalaganju modula; ni uporabniskega vhoda); JS enakovrednik je
// `placilaStripe.racunVNacinu(klub)`. `a` je predpona alias-a tabele, npr. "c." ali "cs.".
const sqlRacunVNacinu = (a = "") => `(COALESCE(${a}stripe_account_livemode, FALSE) = ${placilaStripe.jeLive() ? "TRUE" : "FALSE"})`;
// Klub ima v TEKOCEM nacinu povezan Stripe racun, ki sprejema placila (kot `nacinPlacila(klub)` v placila_stripe.js).
const sqlStripePripravljen = (a = "") => `(${a}stripe_account_id IS NOT NULL AND ${a}stripe_charges_enabled AND ${sqlRacunVNacinu(a)})`;
// Nakup pri tem klubu gre skozi Stripe (javni `payment_mode`, `GET /business/sales`): racun kluba v tekocem nacinu ALI prodajalec je platforma (I50, `clubs.is_official`: neposredno
// placilo na platformni racun, racun kluba ni pogoj). SQL enakovrednik `placilaStripe.nacinPlacila`. Stanje Stripa za lastnika/admina (`sqlStripeStanje`) ostane stanje KLUBOVEGA racuna.
const sqlPlacilaPripravljena = (a = "") => `(${sqlStripePripravljen(a)} OR COALESCE(${a}is_official, FALSE))`;
// Stanje Stripa za odgovore (lastnik, admin): vrednost iz baze velja samo, ce je racun iz tekocega nacina, sicer false.
const sqlStripeStanje = (a = "") => `(${a}stripe_charges_enabled AND ${sqlRacunVNacinu(a)}) AS stripe_charges_enabled, (${a}stripe_payouts_enabled AND ${sqlRacunVNacinu(a)}) AS stripe_payouts_enabled`;

// Lastnik vidi še stanje vidnosti in Stripa, ne pa stripe_account_id. Podatki prodajalca (043) so surovi, `seller_complete` doda koda.
// Stanje Stripa je »v tekocem nacinu« (I36): racun iz drugega nacina se kaze kot nepovezan (false).
const stolpciKlubaLastnika = () => `${JAVNI_STOLPCI_KLUBA}, hidden, ${sqlStripeStanje()}, ${STOLPCI_PRODAJALCA}`;

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

// #210: kljuc z `offset` > 0 (do 100000 vrednosti) ali z `limit`, ki ni privzeti 100 (1..200, krat withCoords = do 400 ključev), je zaporedna vrednost ->
// loceni proracun `prosto`. Vroci ostanejo: brez parametrov, `offset=0`, `limit=100` (tudi neveljaven limit = privzeti) in `withCoords=true` s privzetim limitom.
// Odjemalca (iOS APIClient.swift, splet podatki.js) kliceta `GET /clubs` brez parametrov; zemljevid uporablja `/clubs/map`.
function prostKljucKlubov(q) {
  return !!q.city || stevilo(q.offset, 0, 100000) > 0 || stevilo(q.limit, 100, 200) !== 100;
}

// /clubs/map (I17): brez okvira en kljuc; z okvirom stevila kot nizi (JSON.stringify(Infinity) = null bi zlil +/-Infinity), nenavaden bbox mimo.
function kljucZemljevida(surovBbox, okvir) {
  if (!surovBbox) return JSON.stringify(["clubsmap"]);
  if (!okvir || typeof surovBbox !== "string" || surovBbox.length > 100) return null;
  return JSON.stringify(["clubsmap", okvir.map(String)]);
}
// /search (I17): q je prosto besedilo -> loceni proracun (`prosto`) v klicalcu; predolg niz ali nenavaden tip gre mimo.
// Ključ je TOCEN (obrezan) niz, ne male crke: odgovor vsebuje `query` natanko kot ga je poslal odjemalec.
function kljucIskanja(surovQ, surovLimit, q, limit) {
  if (typeof surovQ !== "string" || q.length > 40) return null;
  if (nenavadniParametri([surovLimit], 10)) return null;
  return JSON.stringify(["search", q, limit]);
}

app.get("/clubs", async (req, res) => {
  try {
    // city je prosto besedilo, offset > 0 zaporedna vrednost (#210): loceni majhen proracun (`prosto`), da poplava ne izpodrine vrocih kljucev.
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
    }, { prosto: prostKljucKlubov(req.query) });
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
    // Neobvezni okvir zemljevida: minLat,minLng,maxLat,maxLng
    const b = req.query.bbox;
    let okvir = null;
    if (b) {
      const d = String(b).split(",").map(Number);
      if (d.length !== 4 || d.some(Number.isNaN)) {
        return res.status(400).send("bbox must be minLat,minLng,maxLat,maxLng.");
      }
      okvir = d;
    }
    // Odgovor ne zavisi od uporabnika (I17). Okvir ima loceni proracun (`prosto`): premikanje zemljevida da vsakic nov kljuc.
    const { vnos, stanje } = await javniPredpomnilnik.dobi(kljucZemljevida(b, okvir), async () => {
      const p = [];
      const pogoji = ["lat IS NOT NULL", "lng IS NOT NULL", "hidden = FALSE"];
      if (okvir) {
        p.push(okvir[0], okvir[2], okvir[1], okvir[3]);
        pogoji.push("lat BETWEEN $1 AND $2", "lng BETWEEN $3 AND $4");
      }
      const r = await pool.query(
        `SELECT id, name, lat, lng, logo_url, city, min_age, genres, is_demo
         FROM clubs WHERE ${pogoji.join(" AND ")} ORDER BY id LIMIT 1000`,
        p
      );
      return { status: 200, json: r.rows };
    }, { prosto: !!okvir });
    return javniPredpomnilnik.poslji(req, res, vnos, stanje);
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
        `SELECT ${JAVNI_STOLPCI_KLUBA}, ${STOLPCI_PRODAJALCA} FROM clubs WHERE id=$1 AND hidden = FALSE`, [req.params.id]
      );
      if (r.rows.length === 0) return { status: 404, besedilo: "Club not found." };
      // Surova polja prodajalca ostanejo na strezniku; javnost dobi `seller` (043, #94). Odvisen je samo od kluba (I17).
      const { legal_name, legal_address, registration_number, tax_number, vat_payer, ...javno } = r.rows[0];
      javno.seller = prodajalec(r.rows[0]);
      return { status: 200, json: { ...javno, is_following: false }, podatki: javno, glave: { Vary: "Authorization" } };
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
    // Organizator brez prizorisca (037): isti profil kot klub, brez obveznega mesta/naslova. is_official NI vhod (samo admin pot, 037).
    const isOrganizer = req.body.isOrganizer ?? req.body.is_organizer;
    if (isOrganizer !== undefined && typeof isOrganizer !== "boolean") return res.status(400).send("isOrganizer must be true or false.");

    if (!name) return res.status(400).send("Missing name.");

    // URL polja (#269): samo http(s); website/instagram brez sheme dobita https://; null in "" = prazno.
    const urlK = preveriUrlPolja([["logo_url", logoUrl], ["banner_url", bannerUrl], ["website", website, { normaliziraj: true }], ["instagram", instagram, { normaliziraj: true, instagram: true }]]);
    if (urlK.napaka) return res.status(400).json(urlK.napaka);

    // Zanri: neznan zanr = 400 (preveriZanre); manjkajoce ali null = brez zanrov (kot doslej).
    const zanriKluba = (genres === undefined || genres === null) ? [] : preveriZanre(genres, res);
    if (!zanriKluba) return;

    const r = await pool.query(
      `INSERT INTO clubs
      (owner_user_id, name, logo_url, banner_url, description,
       contact_email, contact_phone, instagram, website,
       address, city, country, lat, lng, min_age, genres, is_organizer)
       VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
       RETURNING ${stolpciKlubaLastnika()}`,
      [
        req.user.userId,
        name,
        urlK.vrednosti.logo_url || "",
        urlK.vrednosti.banner_url || "",
        description || "",
        contactEmail || "",
        contactPhone || "",
        urlK.vrednosti.instagram || "",
        urlK.vrednosti.website || "",
        address || "",
        city || "",
        country || "",
        lat ?? null,
        lng ?? null,
        minAge ?? 18,
        zanriKluba,
        isOrganizer === true
      ]
    );

    res.status(201).json(dodajSellerComplete(r.rows[0]));
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

// Omejitev podpisov (S2, 17. 10. 2026): brez nje je vsak registriran uporabnik lahko v zanki nalagal datoteke na Outlyjev Cloudinary
// (placljiv prostor in promet). En podpis = eno nalaganje; najvecji tok (galerija kluba 3 slike + logo + video + plakati dogodkov)
// je dalec pod 60/h. Meja je na UPORABNIKA (I15, tabela omejitve), skupna obema potema. Okvara omejevalnika: lokalni stevec.
// allowed_formats NI v podpisu: oba odjemalca (iOS APIClient.uploadToCloudinary, splet api.js naloziNaCloudinary) posljeta Cloudinaryju
// samo vnaprej znana polja (api_key, timestamp, folder, public_id, signature), zato bi razsirjen podpis podrl nalaganje (Invalid Signature).
const PODPIS_CLOUDINARY_NA_URO = okoljeCelo("PODPIS_CLOUDINARY_NA_URO", 60, 1, 10000);
const omejiPodpis = omeji({ kljuc: "cloudinary-podpis", najvec: PODPIS_CLOUDINARY_NA_URO, oknoSekund: 3600, priNapaki: "lokalno", poUporabniku: true });

// Kanonicna pot. Aplikacija je od zacetka klicala prav to, backend pa je
// streg samo GET /cloudinary/signature -> nalaganje slik je vracalo 404.
// Popravek najdbe P-01.
app.post("/uploads/cloudinary-signature", requireAuth, omejiPodpis, izdajPodpis);

// Stara pot. Ohranjena, da nic ne odpove med prehodom. Odstrani jo, ko bo
// v obtoku samo se nova razlicica aplikacije.
app.get("/cloudinary/signature", requireAuth, omejiPodpis, izdajPodpis);

// ---------------------------
// BUSINESS: my club (owner-only)
// ---------------------------
app.get("/business/clubs/me", requireAuth, requireClub(), async (req, res) => {
  try {
    if (!req.klub.clubId) return res.status(404).send("Club not found.");
    const r = await pool.query(
      `SELECT ${stolpciKlubaLastnika()} FROM clubs WHERE id=$1`,
      [req.klub.clubId]
    );

    if (r.rows.length === 0) return res.status(404).send("Club not found.");
    return res.status(200).json({ ...dodajSellerComplete(r.rows[0]), my_role: req.klub.role });
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

    // Podatki prodajalca (043, #94): spremeni jih lahko SAMO lastnik. Manager, ki posle katerokoli od teh polj (tudi null ali isto vrednost),
    // dobi 403 owner_only PRED vsako drugo spremembo (nic se ne zapise); ostala polja managerju delajo kot doslej. Admin (role "admin") sme.
    const prodajalecVTelesu = PRODAJALEC_POLJA.some(([stolpec, camel]) => poljeTelesa(body, camel, stolpec) !== undefined);
    if (prodajalecVTelesu && req.klub.role !== "owner" && req.klub.role !== "admin") {
      return res.status(403).json({ error: "owner_only", message: "Only the club owner can change seller details." });
    }
    const pp = preveriPodatkeProdajalca(body);
    if (pp.napaka) return res.status(400).send(pp.napaka);

    const incoming = {
      ...pp.polja,
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
      video_url: body.video_url ?? body.videoUrl,
      // Organizator brez prizorisca (037). is_official NAMENOMA ni tu: nastavi ga samo admin (PATCH /admin/api/clubs/:id).
      is_organizer: body.is_organizer ?? body.isOrganizer
    };
    if (incoming.is_organizer !== undefined && typeof incoming.is_organizer !== "boolean") {
      return res.status(400).send("isOrganizer must be true or false.");
    }

    // URL polja kluba (#269): samo http(s), napaka 400 invalid_url. Nespremenjena vrednost (tudi stara neveljavna) se ne preverja,
    // ker iOS ob vsakem shranjevanju poslje vsa polja. Stari zapisi se ne cistijo. Pred vsakim zapisom, zato se ob napaki nic ne zapise.
    const urlPolja = [["logo_url", incoming.logo_url], ["banner_url", incoming.banner_url], ["website", incoming.website, { normaliziraj: true }],
      ["instagram", incoming.instagram, { normaliziraj: true, instagram: true }]];
    if (urlPolja.some(([, v]) => v !== undefined)) {
      const stare = (await pool.query("SELECT logo_url, banner_url, website, instagram FROM clubs WHERE id=$1", [clubId])).rows[0];
      const urlK = preveriUrlPolja(urlPolja, stare);
      if (urlK.napaka) return res.status(400).json(urlK.napaka);
      Object.assign(incoming, urlK.vrednosti);
    }

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
      incoming.genres = preveriZanre(incoming.genres, res);
      if (!incoming.genres) return;
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
      const cur = await pool.query(`SELECT ${stolpciKlubaLastnika()} FROM clubs WHERE id=$1`, [clubId]);
      return res.status(200).json(dodajSellerComplete(cur.rows[0]));
    }

    if (incoming.name !== undefined && String(incoming.name).trim().length === 0) {
      return res.status(400).send("Club name is required.");
    }
    // Koordinati v paru; posamezno ju baza zavrne (clubs_coords_chk).
    if ((incoming.lat === undefined) !== (incoming.lng === undefined)) {
      return res.status(400).send("lat and lng must be sent together.");
    }

    values.push(clubId);
    const sql = `UPDATE clubs SET ${sets.join(", ")} WHERE id = $${idx} RETURNING ${stolpciKlubaLastnika()}`;

    const updated = await pool.query(sql, values);
    return res.status(200).json(dodajSellerComplete(updated.rows[0]));
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
           -- Razpored dogodka (039): vir 'event' = mize z event_id = dogodek, sicer klubske mize (event_id IS NULL).
           AND (CASE WHEN events.vip_layout_source = 'event' THEN vct.event_id = events.id ELSE vct.event_id IS NULL END)
           AND NOT COALESCE(vet.disabled, FALSE))`;

// Prizorisce dogodka (migracija 037, organizatorji brez prizorisca). DODANA polja: dogodek ima ali gostiteljski klub z Outlyja (venue_club_id + ime + logotip,
// podpoizvedbe: skrit klub javno ne obstaja, zato izgine tudi kot prizorisce) ali prosto vpisano lokacijo (venue_name/_address/_city/_lat/_lng); navaden klub
// ju obicajno nima (prazen niz / null) in je prizorisce njegov naslov. Podpoizvedbe se sklicujejo na tabelo `events` (brez vzdevka), kot VIP_OD_CENTOV.
const STOLPCI_PRIZORISCA = `(SELECT vc.id FROM clubs vc WHERE vc.id = events.venue_club_id AND NOT vc.hidden) AS venue_club_id,
        (SELECT vc.name FROM clubs vc WHERE vc.id = events.venue_club_id AND NOT vc.hidden) AS venue_club_name,
        (SELECT vc.logo_url FROM clubs vc WHERE vc.id = events.venue_club_id AND NOT vc.hidden) AS venue_club_logo_url,
        venue_name,
        venue_address,
        venue_city,
        venue_lat,
        venue_lng`;
// Isto za poizvedbe z vzdevkoma e (events) in vcl (LEFT JOIN clubs gostitelja, PRIZORISCE_JOIN).
const PRIZORISCE_E = `vcl.id AS venue_club_id, vcl.name AS venue_club_name, vcl.logo_url AS venue_club_logo_url,
              e.venue_name, e.venue_address, e.venue_city, e.venue_lat, e.venue_lng`;
const PRIZORISCE_JOIN = `LEFT JOIN clubs vcl ON vcl.id = e.venue_club_id`;
// Javni pogledi (iskanje): skrit gostitelj javno ne obstaja.
const PRIZORISCE_JOIN_JAVNO = `LEFT JOIN clubs vcl ON vcl.id = e.venue_club_id AND NOT vcl.hidden`;
// Prizorisce kot niz za mail in PDF vstopnice (ime, naslov, mesto): gostiteljski klub, sicer prosto vpisana lokacija, sicer naslov prodajalca (kluba).
// Vrstica mora imeti polja iz PRIZORISCE_MAIL_STOLPCI in club_name/club_address/club_city. Organizatorjev naslov NIKOLI ni prizorisce, ce ga dogodek ima.
const PRIZORISCE_MAIL_STOLPCI = `vcl.id AS venue_club_id, vcl.name AS venue_club_name, vcl.address AS venue_club_address, vcl.city AS venue_club_city,
            e.venue_name, e.venue_address, e.venue_city`;
function prizoriscePodatki(x) {
  if (x.venue_club_id) return [x.venue_club_name, x.venue_club_address, x.venue_club_city].filter(Boolean).join(", ");
  if (x.venue_name || x.venue_city) return [x.venue_name, x.venue_address, x.venue_city].filter(Boolean).join(", ");
  return [x.club_name, x.club_address, x.club_city].filter(Boolean).join(", ");
}

// Polja prizorisca iz vrstice s PRIZORISCE_E (za gnezdene objekte `event`).
// Naslov prizorisca za polji `address` / `city` v pogledih vstopnic (nakup brez racuna, /me/tickets): gostitelj, sicer prosto vpisano, sicer naslov kluba (alias: e, cl, vcl).
const PRIZORISCE_NASLOV = `CASE WHEN vcl.id IS NOT NULL THEN vcl.address WHEN e.venue_name <> '' OR e.venue_city <> '' THEN e.venue_address ELSE cl.address END AS address,
              CASE WHEN vcl.id IS NOT NULL THEN vcl.city WHEN e.venue_name <> '' OR e.venue_city <> '' THEN e.venue_city ELSE cl.city END AS city`;
function prizoriscePolja(x) {
  return { venue_club_id: x.venue_club_id, venue_club_name: x.venue_club_name, venue_club_logo_url: x.venue_club_logo_url,
    venue_name: x.venue_name, venue_address: x.venue_address, venue_city: x.venue_city, venue_lat: x.venue_lat, venue_lng: x.venue_lng };
}

// Stolpci dogodka na enem mestu (javni GET /events, GET /events/:id, GET /business/events).
const STOLPCI_DOGODKA = `
        id,
        club_id,
        -- Ime prodajalca/organizatorja (037): kartica gostovanega dogodka na strani gostitelja ga kaze. DODANO polje.
        (SELECT cn.name FROM clubs cn WHERE cn.id = events.club_id) AS club_name,
        -- Demo klub (050): prodajalec (events.club_id) je demo klub; nakup je 409 demo_club. DODANO polje.
        (SELECT cd.is_demo FROM clubs cd WHERE cd.id = events.club_id) AS is_demo,
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
        ${VIP_OD_CENTOV} AS vip_from_cents,
        -- Vir razporeda VIP miz (migracija 039): club = tloris kluba, event = razpored tega dogodka. DODANO polje.
        vip_layout_source,
        -- Pavza prodaje (055, I53). DODANI polji: sales_paused = admin/klub je prodajo ustavil (cena ostane); on_sale = nakup (vstopnic ali miz) je ta trenutek
        -- odprt po stanju, pavzi, zacetku in oknu prodaje (isti pogoji kot napakaProdaje brez cene; zalogo pove availability, ceno ticket_price_cents).
        -- Ne zavisi od uporabnika: sme v javni predpomnilnik (I17), ki zaostane najvec 3 s.
        sales_paused,
        (status = 'published' AND NOT sales_paused AND start_at > NOW()
          AND NOT COALESCE((SELECT ch.hidden FROM clubs ch WHERE ch.id = events.club_id), FALSE)
          AND (sales_open_at IS NULL OR sales_open_at <= NOW()) AND (sales_close_at IS NULL OR sales_close_at >= NOW())) AS on_sale,
        ${STOLPCI_PRIZORISCA}`;

// Lahka razlicica seznama (GET /events?lite=true, #114): brez `description` (pri 200 dogodkih je to vecina teze odgovora).
// Polje je IZPUSCENO (ne null). Privzeti odgovor ostane nespremenjen (pravilo "spremembe API-ja so samo dodajanje").
const STOLPCI_DOGODKA_LAHKI = STOLPCI_DOGODKA.replace(/^\s*description,\s*$/m, "");
if (STOLPCI_DOGODKA_LAHKI === STOLPCI_DOGODKA) throw new Error("STOLPCI_DOGODKA_LAHKI: stolpca description ni mogoce izlociti");

// payment_mode (#149, #191): kako se pri tem dogodku placa. DODANO polje v javnih odgovorih (GET /events, GET /events/:id, GET /events/:id/vip, GET /business/events):
//   "test"        nic se ne zaracuna (sistem v testnem nacinu ali sandbox + klub brez Stripa)
//   "stripe"      pravo placilo prek Stripa ali 0 EUR mimo Stripa (I49, I34)
//   "unavailable" nakup bi bil zavrnjen (live kljuc in klub brez Stripa -> 409 za PLACLJIVO; Stripe brez webhook skrivnosti -> 503 za vse)
// Izracun je ISTI kot ob nakupu (placilaStripe.nacinPlacilaZ), odvisen od kluba (prodajalec = events.club_id), NE od uporabnika: sme v javni predpomnilnik (I17).
// Cena 0 EUR gre mimo Stripa; pri klubu brez Stripa ob zivem kljucu je zato kupljiva (I49: "stripe"), le Stripe kljuc brez webhook skrivnosti (503) zavrne tudi 0 EUR. Pomozni stolpec se iz vrstice odstrani; stripe_account_id ne zapusti streznika.
// #220: ob `sk_live_` in nepopolnih podatkih prodajalca (I34) je nakup z zneskom > 0 zavrnjen (409 seller_incomplete), zato je `payment_mode` tam "unavailable"
// (isti pogoj kot nakup: `prodajalecZavraNakup`). Dogodek z vstopnico za 0 EUR ostane "stripe": brezplacno je kupljivo.
// Dogodek je mesanica vstopnic in VIP miz z eno vrednostjo: odloca vstopnica (`ticket_price_cents`), ce obstaja, sicer najcenejsa miza (`vip_from_cents`).
// Pri mesanici (vstopnica 0 EUR + placljiva miza ali obratno) je payment_mode dogodka po vstopnici, nakup drugega dela pa vrne 409;
// natancno za mize je `payment_mode` v GET /events/:id/vip.
// I36: `club_stripe_ready` = racun iz TEKOCEGA nacina (sqlStripePripravljen), zato je funkcija (nacin je znan ob klicu).
const sqlKlubStripePripravljen = () => `(SELECT ${sqlPlacilaPripravljena("cs.")} FROM clubs cs WHERE cs.id = events.club_id) AS club_stripe_ready,
        (SELECT ${sqlProdajalecSurov("cs")} FROM clubs cs WHERE cs.id = events.club_id) AS club_seller_raw`;
function dodajNacinPlacila(vrstice) {
  for (const r of vrstice) {
    const vstopnica = r.ticket_price_cents === null || r.ticket_price_cents === undefined ? null : Number(r.ticket_price_cents);   // null = brez vstopnic na Outlyju
    const vip = r.vip_from_cents === null || r.vip_from_cents === undefined ? null : Number(r.vip_from_cents);   // null = brez VIP miz; sicer najcenejsa miza
    // Dogodek odloca po VSTOPNICI, kadar jo ima (odjemalca gumb vstopnic dolocata samo po payment_mode dogodka; prosta miza ne sme narediti
    // placljive vstopnice "stripe", nakup bi bil 409); po najcenejsi mizi samo, ko vstopnic ni. Natancen za mize je payment_mode v GET /events/:id/vip.
    const brezplacno = vstopnica !== null ? vstopnica === 0 : vip === 0;
    const najvec = vstopnica !== null ? vstopnica : (vip || 0);
    r.payment_mode = javniNacinProdajalca(placilaStripe.nacinPlacilaZ(r.club_stripe_ready === true), r.club_seller_raw || {}, najvec, brezplacno);
    // Demo klub (050): nakup je zavrnjen za vse (tudi 0 EUR), zato "unavailable"; razlog javno NI (kot pri ostalih razlogih, I34): odjemalec ga bere iz `is_demo`.
    // Ne zavisi od uporabnika (I17): vloga admin sme kupiti kljub temu (odjemalec naj prijavljenemu adminu gumb pokaze; strezniku odlocitev vedno pripada).
    if (r.is_demo === true) r.payment_mode = "unavailable";
    // Pavza prodaje (055, I53): nakup je 409, zato "unavailable" (obstojeca vrednost: star iOS/splet gumb onemogocita in pokazeta »Tickets aren't on sale«).
    if (r.sales_paused === true) r.payment_mode = "unavailable";
    delete r.club_stripe_ready;
    delete r.club_seller_raw;
  }
  return vrstice;
}

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
         FROM (SELECT ${STOLPCI_DOGODKA}, ${sqlKlubStripePripravljen()} FROM events WHERE club_id=$1) e
        ORDER BY e.start_at DESC LIMIT 500`,
      [req.klub.clubId, top]
    );
    return res.status(200).json(dodajNacinPlacila(r.rows));
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
// #210: clubId (do 20 znakov, poljubne vrednosti) ima loceni proracun `prosto` (10 % kljucev, pri 300 kljucih 30). Posledica: stran kluba
// (/events?clubId=..) si deli te ključe z iskanjem; pri vec kot ~10 klubih hkrati (po 3 kljuci: upcoming, popular, upcoming=false) se izpodrivajo
// med seboj in vec zahtevkov gre v bazo (vsak najvec enkrat na 3 s na klub, single-flight). Seznam brez filtra ostane vroc.
function prostKljucDogodkov(q) {
  return !!q.clubId;
}
function kljucDogodkov(q) {
  const { clubId, upcoming, popular, lite } = q;
  if (nenavadniParametri([clubId, upcoming, popular, lite], 20)) return null;
  const pop = popular === "true";
  return JSON.stringify(["events", clubId || null, pop ? null : (upcoming === "true" || upcoming === "false" ? upcoming : null), pop, lite === "true"]);
}

// Javni seznam dogodkov (GET /events). Z ?clubId= vrne dogodke kluba IN dogodke, ki jih klub GOSTI (events.venue_club_id, 037);
// vsaka vrstica ima takrat `hosted` (true = dogodek organizatorja z gostiteljem clubId, club_id/club_name ostaneta organizatorjeva).
async function javniSeznamDogodkov(req, res) {
  try {
    const { clubId, upcoming, popular } = req.query;
    const stolpci = (req.query.lite === "true" ? STOLPCI_DOGODKA_LAHKI : STOLPCI_DOGODKA) + ", " + sqlKlubStripePripravljen();

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
      return { status: 200, json: dodajNacinPlacila(r.rows) };
    }

    const params = [];
    const where = [];

    if (clubId) {
      params.push(clubId);
      where.push(`(club_id = $${params.length} OR venue_club_id = $${params.length})`);
      // Skrit klub javno ne obstaja: tudi dogodki, ki jih (kot gostitelj) gosti, se na njegovi strani ne kazejo.
      where.push(`NOT EXISTS (SELECT 1 FROM clubs hc WHERE hc.id = $${params.length} AND hc.hidden)`);
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
      SELECT ${stolpci}${clubId ? `, (club_id <> $1) AS hosted` : ""}
      FROM events
      WHERE ${where.join(" AND ")}
      ORDER BY start_at ASC
      LIMIT 200
    `;

    const r = await pool.query(sql, params);
    return { status: 200, json: dodajNacinPlacila(r.rows) };
    }, { prosto: prostKljucDogodkov(req.query) });
    return javniPredpomnilnik.poslji(req, res, vnos, stanje);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
}
app.get("/events", javniSeznamDogodkov);

// neobveznaPrijava: brez zetona pot dela naprej (javna stran dogodka), z zetonom pove
// se moj_plan in nacrte prijateljev (glej ZANIMANJE ZA DOGODEK spodaj, migracija 020).
// Predpomnimo samo javni del (vrstica dogodka); my_plan, friends_going, friends_interested so osebni in se
// izracunajo po branju iz predpomnilnika, v svoji kopiji (I17, I11).
app.get("/events/:id", neobveznaPrijava, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).send("Invalid event id.");
    const { vnos, stanje } = await javniPredpomnilnik.dobi(kljucId("event", req.params.id), async () => {
      const r = await pool.query(
        `SELECT ${STOLPCI_DOGODKA}, ${sqlKlubStripePripravljen()}, ${SQL_PRODAJALEC_DOGODKA} FROM events
         WHERE id=$1 AND status='published'
           AND club_id NOT IN (SELECT id FROM clubs WHERE hidden)`,
        [req.params.id]
      );
      if (r.rows.length === 0) return { status: 404, besedilo: "Event not found." };
      dodajNacinPlacila(r.rows);
      dodajProdajalca(r.rows);   // seller (043, #94): prodajalec = events.club_id, odvisen samo od kluba -> sme v javni predpomnilnik (I17)
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

// ---------------------------
// PRIZORISCE DOGODKA (migracija 037, organizatorji brez prizorisca)
// ---------------------------
// Dogodek ima ali gostiteljski klub z Outlyja (venue_club_id) ali prosto vpisano lokacijo (venue_name/_address/_city/_lat/_lng). Organizator (clubs.is_organizer)
// MORA podati eno od obeh (400 »Organizer events need a venue.«); navaden klub sme, ni pa obvezno (prizorisce je tedaj njegov naslov).
// Ce je venue_club_id podan, se prosta polja pocistijo (prazen niz / null). Gostitelj ne sme biti klub sam (400), mora obstajati in ne biti skrit (404).
// Prizorisce NE spremeni prodajalca (events.club_id) in ne tega, kdo skenira (I26).
const PRIZORISCE_NAJVEC = { venue_name: 120, venue_address: 200, venue_city: 100 };
// Iz telesa zahtevka (camelCase ali snake_case) samo polja, ki so podana. Vrne { dano } ali { napaka: "besedilo" } (400).
function prizoriscaIzTelesa(b) {
  const dano = {};
  const v = (...imena) => { for (const i of imena) if (b[i] !== undefined) return b[i]; return undefined; };
  const klub = v("venueClubId", "venue_club_id");
  if (klub !== undefined) {
    if (klub === null || klub === "") dano.venue_club_id = null;
    else if (!/^\d+$/.test(String(klub)) || Number(klub) < 1 || Number(klub) > INT4_MAX) return { napaka: "venueClubId must be a club id." };
    else dano.venue_club_id = Number(klub);
  }
  for (const [kljuc, ...imena] of [["venue_name", "venueName", "venue_name"], ["venue_address", "venueAddress", "venue_address"], ["venue_city", "venueCity", "venue_city"]]) {
    const x = v(...imena);
    if (x === undefined) continue;
    if (x !== null && typeof x !== "string") return { napaka: `${imena[0]} must be a string.` };
    const t = x === null ? "" : x.trim();
    if (t.length > PRIZORISCE_NAJVEC[kljuc]) return { napaka: `${imena[0]} too long (max ${PRIZORISCE_NAJVEC[kljuc]}).` };
    dano[kljuc] = t;
  }
  const lat = v("venueLat", "venue_lat"), lng = v("venueLng", "venue_lng");
  if ((lat === undefined) !== (lng === undefined)) return { napaka: "venueLat and venueLng must be sent together." };
  if (lat !== undefined) {
    if (lat === null && lng === null) { dano.venue_lat = null; dano.venue_lng = null; }
    else {
      const st = (x) => ((typeof x === "number" || (typeof x === "string" && x.trim() !== "")) ? Number(x) : NaN);
      const a = st(lat), o = st(lng);
      if (!Number.isFinite(a) || !Number.isFinite(o) || a < -90 || a > 90 || o < -180 || o > 180) return { napaka: "venueLat/venueLng out of range." };
      dano.venue_lat = a; dano.venue_lng = o;
    }
  }
  return { dano };
}
const PRAZNO_PRIZORISCE = { venue_club_id: null, venue_name: "", venue_address: "", venue_city: "", venue_lat: null, venue_lng: null };
// Z gostiteljem so prosta polja prazna (gostitelj ima prednost; polja se ignorirajo).
function uskladiPrizorisce(stanje) {
  return stanje.venue_club_id ? { ...PRAZNO_PRIZORISCE, venue_club_id: stanje.venue_club_id } : { ...stanje, venue_club_id: null };
}
// Preveri stanje prizorisca; ob napaki sam poslje odgovor in vrne false. `clubId` = prodajalec (dogodek), `jeOrganizator` = clubs.is_organizer.
async function preveriPrizorisce(stanje, clubId, jeOrganizator, res) {
  if (stanje.venue_club_id) {
    if (Number(stanje.venue_club_id) === Number(clubId)) { res.status(400).send("venueClubId must be a different club than the event's club."); return false; }
    const g = await pool.query("SELECT 1 FROM clubs WHERE id=$1 AND hidden = FALSE", [stanje.venue_club_id]);
    if (g.rows.length === 0) { res.status(404).send("Venue club not found."); return false; }
  } else if (jeOrganizator && !(stanje.venue_name && stanje.venue_city)) {
    res.status(400).send("Organizer events need a venue.");
    return false;
  }
  return true;
}
// Odgovor POST/PATCH /events (RETURNING *) dobi se ime in logotip gostitelja, da je oblika enaka kot v GET /events.
async function dopolniPrizorisce(vrstica) {
  let ime = null, logo = null;
  if (vrstica.venue_club_id) {
    const g = await pool.query("SELECT name, logo_url FROM clubs WHERE id=$1", [vrstica.venue_club_id]);
    if (g.rows[0]) { ime = g.rows[0].name; logo = g.rows[0].logo_url; }
  }
  return { ...vrstica, venue_club_name: ime, venue_club_logo_url: logo };
}

// POST /events (updated: accepts camelCase + snake_case, includes ticket fields)
app.post("/events", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    // accept both formats
    const clubId = req.body.clubId ?? req.body.club_id;
    const title = req.body.title;
    const description = req.body.description ?? "";
    const posterUrlSurov = req.body.posterUrl ?? req.body.poster_url;
    const startAt = req.body.startAt ?? req.body.start_at;
    const endAt = req.body.endAt ?? req.body.end_at ?? null;
    const minAge = req.body.minAge ?? req.body.min_age;
    const genres = req.body.genres;
    const status = req.body.status ?? "published";

    const ticketPriceCents = req.body.ticketPriceCents ?? req.body.ticket_price_cents ?? null;
    const currency = (req.body.currency ?? "EUR").toString();
    const ticketUrlSurov = req.body.ticketUrl ?? req.body.ticket_url;
    const capacity = req.body.capacity ?? null;
    if (capacity !== null) {
      const c = Number(capacity);
      if (!Number.isInteger(c) || c < 1 || c > 100000) return res.status(400).send("capacity must be a positive integer.");
    }

    if (!clubId || !title || !startAt) return res.status(400).send("Missing clubId, title or startAt.");
    if (!/^\d+$/.test(String(clubId))) return res.status(400).send("Invalid clubId.");
    // URL polja (#269): samo http(s), 400 invalid_url; brez polja ali null = "".
    const urlD = preveriUrlPolja([["poster_url", posterUrlSurov], ["ticket_url", ticketUrlSurov]]);
    if (urlD.napaka) return res.status(400).json(urlD.napaka);
    const posterUrl = urlD.vrednosti.poster_url || "";
    const ticketUrl = urlD.vrednosti.ticket_url || "";
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
    const zanriDogodka = genres === undefined ? undefined : preveriZanre(genres, res);
    if (genres !== undefined && !zanriDogodka) return;
    if (minAge !== undefined && minAge !== null) {
      const a = Number(minAge);
      if (!Number.isInteger(a) || a < 0 || a > 99) return res.status(400).send("minAge must be between 0 and 99.");
    }

    const pz = prizoriscaIzTelesa(req.body);
    if (pz.napaka) return res.status(400).send(pz.napaka);

    const clubR = await pool.query("SELECT id, owner_user_id, min_age, genres, is_organizer FROM clubs WHERE id=$1", [clubId]);
    if (clubR.rows.length === 0) return res.status(404).send("Club not found.");

    const club = clubR.rows[0];

    if (req.klub.role !== "admin" && Number(club.id) !== Number(req.klub.clubId)) {
      return res.status(403).send("You can only create events for your own club.");
    }

    // Prizorisce (037): gostiteljski klub ali prosta lokacija; organizator ga mora podati.
    const prizorisce = uskladiPrizorisce({ ...PRAZNO_PRIZORISCE, ...pz.dano });
    if (!(await preveriPrizorisce(prizorisce, club.id, club.is_organizer, res))) return;

    const finalMinAge = (minAge ?? club.min_age ?? 18);
    // Podedovani zanri kluba so lahko stari zapisi izven ZANRI: ociscimo (brez 400, neznane izpustimo), da se umazanija ne siri na nove dogodke.
    const finalGenres = zanriDogodka ?? ociscenoZanre(club.genres);

    const r = await pool.query(
      `INSERT INTO events
      (
        club_id, title, description, poster_url, start_at, end_at,
        min_age, genres, status,
        ticket_price_cents, currency, ticket_url, capacity,
        venue_club_id, venue_name, venue_address, venue_city, venue_lat, venue_lng
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
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
        capacity,
        prizorisce.venue_club_id,
        prizorisce.venue_name,
        prizorisce.venue_address,
        prizorisce.venue_city,
        prizorisce.venue_lat,
        prizorisce.venue_lng
      ]
    );

    // Sledilci kluba dobijo obvestilo (migracija 019). Samo objavljeni dogodki:
    // osnutka in odpovedanega ni smisla oznanjati. Napaka pri obvescanju NE sme
    // podreti ustvarjanja dogodka — ta je ze v bazi.
    if (r.rows[0].status === "published") {
      try { await obvestiSledilce(r.rows[0].id, clubId); }
      catch (e) { console.error("Obvescanje sledilcev ni uspelo:", e.message); }
    }

    res.status(201).json(await dopolniPrizorisce(r.rows[0]));
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// Vsakemu sledilcu kluba vstavi obvestilo o dogodku. UNIQUE (user_id, event_id) poskrbi,
// da ponovna objava (draft -> published -> draft -> published) ne podvoji zvonca.
// Push (040): samo tisti, ki so pravkar dobili NOVO vrstico (RETURNING), po commitu stavka, brez await (I29).
async function obvestiSledilce(eventId, clubId) {
  const r = await pool.query(
    `INSERT INTO club_event_notifications (user_id, event_id)
     SELECT f.user_id, $1 FROM club_follows f WHERE f.club_id = $2
     ON CONFLICT (user_id, event_id) DO NOTHING
     RETURNING user_id`,
    [eventId, clubId]
  );
  if (r.rows.length) void pushObjavaDogodka(eventId, r.rows.map((x) => x.user_id));
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
    `SELECT e.id, e.club_id, e.status, c.owner_user_id, c.is_organizer, e.poster_url, e.ticket_url,
            e.venue_club_id, e.venue_name, e.venue_address, e.venue_city, e.venue_lat, e.venue_lng,
            (COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') <= NOW()) AS je_koncan
     FROM events e JOIN clubs c ON c.id = e.club_id
     WHERE e.id = $1`,
    [req.params.id]
  );
  if (r.rows.length === 0) { res.status(404).send("Event not found."); return null; }

  const d = r.rows[0];
  // Vloga admin iz baze (I5) sme tuj dogodek tudi, ce je sam lastnik/clan nekega kluba (req.klub je tedaj njegov klub, ne { role: 'admin' }).
  if (!jeAdminDogodka(req) && Number(d.club_id) !== Number(req.klub.clubId)) {
    res.status(403).send("You can only manage events of your own club.");
    return null;
  }
  return d;
}

// #255 (invarianta I42): odpoved dogodka s placanimi narocili vrne denar VSEM kupcem (vracila_stripe.js, I37). Lastnik/manager tega ne sme sprozit za dogodek,
// ki je ze MINIL (jeDogodekMinil, sken_okno.js) ali ima vsaj eno UNOVCENO vstopnico (`used`: gost je ze vstopil) - vracila takrat ureja Outly (admin panel ali
// vloga admin na isti poti). Isto velja za premik datuma minilega dogodka (sicer: premakni v prihodnost, nato odpovej). Brez placanih narocil se nic ne spremeni.
// Sporocilo vsebuje »already started«: star iOS (APIErrorMessages) in splet (napake.js PRAVILA) ga po tem nizu prevedeta v »This event has already started.«
// (brez tega bi 409 pokazal »This is already in use.«). Nov odjemalec naj bere `error`.
const NAPAKA_DOGODEK_MINIL = { error: "event_finished", message: "This event has already started or taken place, so it can't be cancelled. Contact Outly for refunds." };
const NAPAKA_DOGODEK_MINIL_DATUM = { error: "event_finished", message: "This event has already started or taken place, so its date can't be changed. Contact Outly." };
// --- dnevnik admin dejanj (055, I53) ---
// Vrstica se vpise v ISTI transakciji `c` kot sprememba (klicatelj jo commita ali vrne skupaj). Brez osebnih podatkov kupcev: samo polja cilja.
async function zapisiAdminDejanje(c, req, dejanje, ciljTip, ciljId, prej, potem, razlog) {
  await c.query(
    `INSERT INTO admin_dejanja (admin_user_id, dejanje, cilj_tip, cilj_id, prej, potem, razlog)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)`,
    [req.user.userId, dejanje, ciljTip, String(ciljId), prej === null || prej === undefined ? null : JSON.stringify(prej),
     potem === null || potem === undefined ? null : JSON.stringify(potem), razlog || null]);
}
// Primerljiva vrednost za dnevnik (Date -> ISO, NUMERIC/BIGINT niz ostane niz).
const vrednostDnevnika = (v) => (v instanceof Date ? v.toISOString() : v === undefined ? null : v);
// {prej, potem} samo za polja, ki so se res spremenila; null, ce se ni nic.
function razlikaPolj(polja, star, nov) {
  const prej = {}, potem = {};
  for (const k of polja) {
    const a = vrednostDnevnika(star[k]), b = vrednostDnevnika(nov[k]);
    if (JSON.stringify(a) === JSON.stringify(b)) continue;
    prej[k] = a; potem[k] = b;
  }
  return Object.keys(potem).length ? { prej, potem } : null;
}
// Ime dejanja po najpomembnejsi spremembi (dnevnik ima vedno vsa spremenjena polja).
function dejanjeDogodka(prej, potem) {
  if (potem.status === "cancelled") return "event.cancel";
  if (potem.status === "published") return "event.publish";
  if (potem.status === "draft") return "event.unpublish";
  if (potem.sales_paused === true) return "event.sales_pause";
  if (potem.sales_paused === false) return "event.sales_resume";
  return "event.update";
}
const jeAdminDogodka = (req) => (req.klub && req.klub.role === "admin") || (req.user && req.user.role === "admin");   // vloga iz baze (I5)
// V TRANSAKCIJI: zaklene vrstico dogodka (FOR UPDATE; zaporedi DELETE/PATCH istega dogodka in nakupe, ki zaklenejo isto vrstico) in presteje narocila.
// Sken vrstice dogodka NE zaklepa (I16, sken ostane hiter): sken, ki se zgodi v istih milisekundah kot odpoved (med to poizvedbo in COMMIT), lahko unovci
// vstopnico, ki jo odpoved nato vrne. Okno je sprejeto in dokumentirano v I42 (dolzina transakcije; prva unovcena vstopnica pred odpovedjo jo ze blokira).
async function zaklepDogodkaZaOdpoved(c, id) {
  const r = await c.query(
    `SELECT e.id, e.status, e.start_at, e.end_at,
            (SELECT COUNT(*)::int FROM orders o WHERE o.event_id = e.id AND o.status IN ('paid','partially_refunded')) AS placanih,
            -- samo narocila, ki bi ob odpovedi res dobila DENAR nazaj (pogoj VSTAVI_VRACILA + znesek > 0): guest lista in 0 EUR odpovedi ne zaklenejo (pregled #262 N1)
            (SELECT COUNT(*)::int FROM orders o WHERE o.event_id = e.id AND ${SQL_NAROCILO_ZA_ODPOVED} AND o.total_cents > o.refunded_cents) AS za_vracilo,
            (SELECT COUNT(*)::int FROM orders o WHERE o.event_id = e.id) AS narocil,
            EXISTS (SELECT 1 FROM tickets t WHERE t.event_id = e.id AND t.status = 'used') AS unovceno
       FROM events e WHERE e.id = $1 FOR UPDATE OF e`, [id]);
  return r.rows[0] || null;
}
const { SQL_NAROCILO_ZA_ODPOVED } = require("./vracila_stripe");
const odpovedZaklenjena = (z) => z.za_vracilo > 0 && (jeDogodekMinil(z.start_at, z.end_at) || z.unovceno);
// Ali PATCH datum res spreminja (na minuto natancno: obrazca iOS in splet ob vsakem shranjevanju poslje startAt/endAt, iz izbirnika brez sekund).
const istiCas = (nov, star) => {
  if (nov === null || nov === "") return star === null;
  if (star === null) return false;
  const t = new Date(nov).getTime();
  return Number.isFinite(t) && Math.floor(t / 60000) === Math.floor(new Date(star).getTime() / 60000);
};

// M5 (pregled #316): vloga admin (iz baze, I5) ureja VSE dogodke ne glede na lastno clanstvo v klubu (admin, ki je v nekem klubu vratar ali natakar,
// je prej dobil 403 iz requireClub). Ne-admin gre skozi requireClub("owner", "manager") kot doslej.
function requireClubUrednikDogodka() {
  const zaKlub = requireClub("owner", "manager");
  return (req, res, next) => {
    if (req.user && req.user.role === "admin") { req.klub = { clubId: null, role: "admin" }; return next(); }
    return zaKlub(req, res, next);
  };
}
app.patch("/events/:id", requireAuth, requireClubUrednikDogodka(), async (req, res) => {
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
      // Izrecen null = dogodek brez vstopnic na Outlyju (ustavitev prodaje); izpuscen kljuc = brez spremembe. Samo `??` bi null spremenil v undefined.
      ticket_price_cents: b.ticketPriceCents ?? b.ticket_price_cents ?? (b.ticketPriceCents === null || b.ticket_price_cents === null ? null : undefined),
      currency:           b.currency,
      ticket_url:         b.ticketUrl        ?? b.ticket_url,
      capacity:           b.capacity,
      // Posnetek koncanega dogodka (migracija 019). Prazen niz = odstrani.
      recap_video_url:    b.recapVideoUrl    ?? b.recap_video_url,
    };

    // URL polja (#269): samo http(s), 400 invalid_url. Nespremenjena vrednost (tudi stara neveljavna) se ne preverja (obrazca iOS in splet
    // ob vsakem shranjevanju posljeta vsa polja); stari zapisi se ne cistijo.
    const urlD = preveriUrlPolja([["poster_url", dovoljeno.poster_url], ["ticket_url", dovoljeno.ticket_url]], d);
    if (urlD.napaka) return res.status(400).json(urlD.napaka);
    Object.assign(dovoljeno, urlD.vrednosti);

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

    // Prizorisce (037): preverja se samo, ce ga zahtevek spreminja (urejanje naslova ne sme pasti zaradi starega dogodka brez prizorisca).
    const pz = prizoriscaIzTelesa(b);
    if (pz.napaka) return res.status(400).send(pz.napaka);
    if (Object.keys(pz.dano).length > 0) {
      const stanje = { venue_club_id: d.venue_club_id, venue_name: d.venue_name, venue_address: d.venue_address, venue_city: d.venue_city, venue_lat: d.venue_lat, venue_lng: d.venue_lng, ...pz.dano };
      // Prosto besedilo brez venueClubId prepise gostitelja (urejevalnik poslje bodisi gostitelja bodisi lokacijo).
      if (pz.dano.venue_club_id === undefined && (pz.dano.venue_name || pz.dano.venue_address || pz.dano.venue_city)) stanje.venue_club_id = null;
      const prizorisce = uskladiPrizorisce(stanje);
      if (!(await preveriPrizorisce(prizorisce, d.club_id, d.is_organizer, res))) return;
      Object.assign(dovoljeno, prizorisce);
    }

    if (dovoljeno.capacity !== undefined && dovoljeno.capacity !== null) {
      const c = Number(dovoljeno.capacity);
      if (!Number.isInteger(c) || c < 1 || c > 100000) return res.status(400).send("capacity must be a positive integer.");
    }
    if (dovoljeno.status !== undefined &&
        !["draft","published","cancelled"].includes(dovoljeno.status)) {
      return res.status(400).send("status must be draft, published or cancelled.");
    }
    if (dovoljeno.genres !== undefined) {
      dovoljeno.genres = preveriZanre(dovoljeno.genres, res);
      if (!dovoljeno.genres) return;
    }
    if (dovoljeno.ticket_price_cents !== undefined && dovoljeno.ticket_price_cents !== null) {
      const c = Number(dovoljeno.ticket_price_cents);
      if (!Number.isInteger(c) || c < 0) return res.status(400).send("ticketPriceCents must be a non-negative integer.");
    }

    // Pavza prodaje (055, I53): samo boolean; izpuscen kljuc = brez spremembe.
    const pavzaV = b.salesPaused !== undefined ? b.salesPaused : b.sales_paused;
    if (pavzaV !== undefined) {
      if (typeof pavzaV !== "boolean") return res.status(400).send("salesPaused must be true or false.");
      dovoljeno.sales_paused = pavzaV;
    }

    const sets = [], vrednosti = [];
    for (const [k, v] of Object.entries(dovoljeno)) {
      if (v === undefined) continue;
      vrednosti.push(v);
      sets.push(`${k} = $${vrednosti.length}`);
    }
    if (sets.length === 0) return res.status(400).send("Nothing to update.");

    vrednosti.push(d.id);
    const sqlPosodobi = `UPDATE events SET ${sets.join(", ")} WHERE id = $${vrednosti.length} RETURNING *`;
    let r, prej = null, pavzaOd = null, preklicanih = 0;
    // #255 (I42): odpoved (status -> cancelled) ali premik datuma gre skozi zaklep vrstice in preverbo; admin sme vedno.
    // Vse v ENI transakciji z zaklepom vrstice dogodka (FOR UPDATE: zaporedi hkratne PATCH/DELETE istega dogodka; sken vrstice ne zaklepa, I16):
    //  - admin (I53): stare vrednosti spremenjenih polj in vrstica `admin_dejanja` v ISTI transakciji (sprememba brez vrstice ali vrstica brez spremembe ni mogoca);
    //  - pavza prodaje (055, I53): ob prehodu v ustavljeno se v isti transakciji preklicejo cakajoca narocila z odprtim placilnim oknom, Stripove seje
    //    se zaprejo PO COMMIT-u v ozadju (pavza_prodaje.js); povezave med klici Stripa ne drzimo.
    const odpoved = dovoljeno.status === "cancelled";
    const datum = dovoljeno.start_at !== undefined || dovoljeno.end_at !== undefined;
    const admin = jeAdminDogodka(req);
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      // Odpoved/datum neadmina: polna preverba I42 (steje narocila). Sicer samo kratek zaklep vrstice (FOR NO KEY UPDATE: ne caka na tuje kljuce novih narocil).
      const z = !admin && (odpoved || datum) ? await zaklepDogodkaZaOdpoved(c, d.id)
        : (await c.query("SELECT id FROM events WHERE id = $1 FOR NO KEY UPDATE", [d.id])).rows[0];
      if (!z) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
      if (!admin && odpoved && z.status !== "cancelled" && odpovedZaklenjena(z)) {
        await c.query("ROLLBACK");
        return res.status(409).json(NAPAKA_DOGODEK_MINIL);
      }
      if (!admin && datum && z.za_vracilo > 0 && jeDogodekMinil(z.start_at, z.end_at) &&
          ((dovoljeno.start_at !== undefined && !istiCas(dovoljeno.start_at, z.start_at)) ||
           (dovoljeno.end_at !== undefined && !istiCas(dovoljeno.end_at, z.end_at)))) {
        await c.query("ROLLBACK");
        return res.status(409).json(NAPAKA_DOGODEK_MINIL_DATUM);
      }
      // Pavza (I53): izkljucen advisory zaklep dogodka PO zaklepu vrstice; nakupi in zapis seje ga vzamejo deljenega tik pred COMMIT-om (pavzaPredCommitom).
      if (dovoljeno.sales_paused === true) await c.query("SELECT pg_advisory_xact_lock($1::int, $2::int)", [PAVZA_ZAKLEP_RAZRED, d.id]);
      const polja = Object.keys(dovoljeno).filter((k) => dovoljeno[k] !== undefined);
      const st = (await c.query(`SELECT ${polja.map((k) => `"${k}"`).join(", ")}, NOW() AS zdaj FROM events WHERE id = $1`, [d.id])).rows[0];
      prej = st;
      r = await c.query(sqlPosodobi, vrednosti);
      if (st.sales_paused !== true && r.rows[0].sales_paused === true) {
        pavzaOd = st.zdaj;
        preklicanih = await pavzaProdaje.prekliciCakajoca(c, d.id);
      }
      if (admin) {
        const dnevnik = razlikaPolj(polja, st, r.rows[0]);
        if (dnevnik) await zapisiAdminDejanje(c, req, dejanjeDogodka(dnevnik.prej, dnevnik.potem), "event", d.id, dnevnik.prej, dnevnik.potem);
      }
      await c.query("COMMIT");
    } catch (e) {
      await c.query("ROLLBACK").catch(() => {});
      // U2: kapaciteta pod ze prodanim (omejitev events_sold_chk) je napaka vnosa, ne strežnika.
      if (e && e.code === "23514" && e.constraint === "events_sold_chk") {
        const sold = (await c.query("SELECT sold_count FROM events WHERE id = $1", [d.id]).catch(() => ({ rows: [] }))).rows[0];   // M8: ze drzimo c (I16, #274)
        return res.status(400).json({ error: "capacity_below_sold", message: `Capacity can't be lower than the number of tickets already sold${sold ? ` (${sold.sold_count})` : ""}.`, sold: sold ? sold.sold_count : null });
      }
      // Preklic cakajocih narocil ob pavzi (zaklep dogodek -> narocila) se lahko redko zaklene s hkratnim webhookom (narocilo -> dogodek prek sprozilca):
      // Postgres eno od transakcij prekine; tu nic ni spremenjeno, odjemalec ponovi.
      if (e && (e.code === "40P01" || e.code === "55P03")) return res.status(503).set("Retry-After", "2").send("The event is busy. Please try again.");
      throw e;
    } finally { c.release(); }
    razprodanoPozabi("v:" + d.id);   // capacity ali status se je morda spremenil
    if (pavzaOd) {
      console.log(`[pavza] dogodek ${d.id}: prodaja ustavljena (uporabnik ${req.user.userId}), preklicanih cakajocih narocil ${preklicanih}`);
      void pavzaOkna.zazeni(d.id, pavzaOd);   // po COMMIT-u, brez await: odgovor ne caka na Stripe
    } else if (prej && prej.sales_paused === true && r.rows[0].sales_paused === false) {
      console.log(`[pavza] dogodek ${d.id}: prodaja spet tece (uporabnik ${req.user.userId})`);
    }

    // Dogodek je sele zdaj postal objavljen -> sledilci kluba dobijo obvestilo (migracija 019).
    if (d.status !== "published" && r.rows[0].status === "published") {
      try { await obvestiSledilce(r.rows[0].id, d.club_id); }
      catch (e) { console.error("Obvescanje sledilcev ni uspelo:", e.message); }
    }

    return res.status(200).json(await dopolniPrizorisce(r.rows[0]));
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.delete("/events/:id", requireAuth, requireClubUrednikDogodka(), async (req, res) => {
  try {
    const d = await dogodekZaUrejanje(req, res);
    if (!d) return;

    if (!obstajajoNarocila) {   // pred migracijo 002 narocil ni
      await pool.query("DELETE FROM events WHERE id=$1", [d.id]);
      return res.status(200).json({ message: "Event deleted." });
    }

    // Vse v ENI transakciji z zaklepom vrstice dogodka (zaklepDogodkaZaOdpoved): preverba #255, stetje narocil in izbris/odpoved vidijo isto sliko.
    // - Brez narocil: izbris kot doslej.
    // - S katerimkoli narocilom: dogodek se NE brise (narocilo je racunovodski dokument; FK orders_event_id_fkey je RESTRICT, prej je to dalo 500, #258 N2),
    //   ampak odpove. Placana narocila (paid/partially_refunded) gredo v vrsto vracil v ISTI transakciji (#190, I37): denar vrne obdelovalec v ozadju
    //   (vracila_stripe.js), odpoved ostane hitra tudi pri tisocih narocilih. Ponovni DELETE ne podvoji (UNIQUE order_id, razlog). Brez placanih
    //   (samo pending/preklicana/vrnjena) vrstiZaDogodek vstavi 0 vrstic, a dogodek zabelezi v odpovedi_dogodkov: ce se cakajoce narocilo placa
    //   po odpovedi, ga sweep vrne (I37).
    // - Lastnik/manager: odpoved s placanimi narocili minilega dogodka ali dogodka z unovceno vstopnico -> 409 event_finished (#255, I42). Admin sme.
    const c = await pool.connect();
    let r, vVrsti, z;
    try {
      await c.query("BEGIN");
      z = await zaklepDogodkaZaOdpoved(c, d.id);
      if (!z) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
      if (z.narocil === 0) {
        await c.query("DELETE FROM events WHERE id=$1", [d.id]);
        if (jeAdminDogodka(req)) await zapisiAdminDejanje(c, req, "event.delete", "event", d.id, { status: z.status }, null);   // I53: v isti transakciji
        await c.query("COMMIT");
        return res.status(200).json({ message: "Event deleted." });
      }
      if (!jeAdminDogodka(req) && odpovedZaklenjena(z)) {
        await c.query("ROLLBACK");
        return res.status(409).json(NAPAKA_DOGODEK_MINIL);
      }
      r = await c.query("UPDATE events SET status='cancelled' WHERE id=$1 RETURNING *", [d.id]);
      vVrsti = await vracilaStripe.vrstiZaDogodek(c, d.id);
      if (jeAdminDogodka(req) && z.status !== "cancelled") await zapisiAdminDejanje(c, req, "event.cancel", "event", d.id, { status: z.status }, { status: "cancelled" });   // I53
      await c.query("COMMIT");
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
    finally { c.release(); }
    razprodanoPozabi("v:" + d.id);
    if (vVrsti > 0) vracilaStripe.zbudi();
    if (z.placanih > 0 && jeAdminDogodka(req)) console.log(`Admin ${req.user.userId} je odpovedal dogodek ${d.id} (${z.placanih} placanih narocil)`);
    return res.status(200).json({
      message: z.placanih > 0 ? "Event has sold tickets and was cancelled instead of deleted." : "Event has orders and was cancelled instead of deleted.",
      orders: z.placanih,
      refunds_queued: vVrsti,
      event: r.rows[0],
    });
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

    // Odgovor ne zavisi od uporabnika (I17); iskalni nizi so prosto besedilo -> loceni proracun (`prosto`).
    const { vnos, stanje } = await javniPredpomnilnik.dobi(kljucIskanja(req.query.q, req.query.limit, q, limit), async () => {
    const [klubi, dogodki] = await Promise.all([
      pool.query(
        `SELECT id, name, city, logo_url, lat, lng, genres, is_demo
         FROM clubs
         WHERE hidden = FALSE
           AND (name ILIKE $1 OR city ILIKE $1 OR description ILIKE $1)
         ORDER BY (name ILIKE $2) DESC, name
         LIMIT $3`,
        [vzorec, `${q}%`, limit]
      ),
      pool.query(
        `SELECT e.id, e.club_id, e.title, e.poster_url, e.start_at,
                e.ticket_price_cents, e.currency, c.name AS club_name, c.is_demo, ${PRIZORISCE_E}
         FROM events e JOIN clubs c ON c.id = e.club_id ${PRIZORISCE_JOIN_JAVNO}
         WHERE e.status = 'published' AND c.hidden = FALSE
           AND (e.title ILIKE $1 OR e.description ILIKE $1 OR c.name ILIKE $1)
         ORDER BY (e.start_at > NOW()) DESC, e.start_at
         LIMIT $2`,
        [vzorec, limit]
      ),
    ]);

    return { status: 200, json: {
      query: q,
      clubs: klubi.rows,
      events: dogodki.rows,
      total: klubi.rows.length + dogodki.rows.length,
    } };
    }, { prosto: true });
    return javniPredpomnilnik.poslji(req, res, vnos, stanje);
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
// Stanje Stripa je »v tekocem nacinu« (I36, sqlRacunVNacinu).
const adminStolpciKluba = () => `c.id, c.owner_user_id, c.name, c.logo_url, c.banner_url, c.description,
  c.contact_email, c.contact_phone, c.instagram, c.website, c.address, c.city, c.country,
  c.lat, c.lng, c.min_age, c.genres, c.hidden, (c.stripe_charges_enabled AND ${sqlRacunVNacinu("c.")}) AS stripe_charges_enabled, c.commission_bps, c.created_at,
  c.is_organizer, c.is_official, c.is_demo,
  (c.stripe_account_id IS NOT NULL) AS has_stripe_account, (SELECT COUNT(*)::int FROM orders ord WHERE ord.club_id = c.id) AS order_count,   -- za opozorilo ob vklopu »uradni profil« (I50); racun sam ne uhaja
  c.legal_name, c.legal_address, c.registration_number, c.tax_number, c.vat_payer,
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
// Zadeva maila (#275): nove vrstice in kontrolni znaki ven (glave), presledki strnjeni, dolzina omejena. Uporabniski vnos v zadevi
// je dovoljen samo, kjer ga bere ekipa ali lastnik racuna; prejemniku, ki ga vnos ni sam sprozil, gre nevtralna zadeva.
function zadevaMaila(s, najvec = 200) {
  const t = String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").replace(/\s+/g, " ").trim();
  return t.length > najvec ? t.slice(0, najvec - 1) + "…" : t;
}
async function posljiMailProsnja(p) {
  if (!resend) return;
  const from = process.env.EMAIL_FROM || "onboarding@resend.dev";
  const appName = process.env.APP_NAME || "Outly";
  const ekipa = String(process.env.TEAM_EMAIL || "luka@outly.si,fedja@outly.si").split(",").map(e => e.trim()).filter(Boolean);
  const vrstica = (k, v) => v ? `<tr><td style="padding:4px 12px 4px 0;color:#666">${k}</td><td style="padding:4px 0"><b>${ubeziHtml(v)}</b></td></tr>` : "";
  try {
    const r1 = await resend.emails.send({
      from, to: ekipa, replyTo: p.email,
      subject: zadevaMaila(`Nova prošnja ustvarjalca: ${p.businessName}`),
      html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – nova prošnja ustvarjalca (#${p.id})</h2>
      <table>${vrstica("Podjetje", p.businessName)}${vrstica("Vrsta", p.businessType)}${vrstica("Naslov", p.businessAddress)}${vrstica("Kraj", p.city)}${vrstica("Licenca", p.licenceId)}${vrstica("Kontakt", p.contactName)}${vrstica("Vloga", p.contactRole)}${vrstica("E-naslov", p.email)}${vrstica("Telefon", p.phone)}${vrstica("Sporočilo", p.message)}${vrstica("Vir", p.userId ? "aplikacija (uporabnik #" + p.userId + ")" : "spletna stran")}</table>
      <p>Odobri ali zavrni v admin panelu: <a href="https://outly-backend-roy3.onrender.com/admin/">outly-backend-roy3.onrender.com/admin</a> → Prošnje.</p>
    </div>`,
    });
    if (r1 && r1.error) console.error("Resend napaka (prošnja, ekipa):", JSON.stringify(r1.error));
    // Potrdilo samo prijavljenemu na preverjen naslov njegovega racuna (p.potrdiloNa), nikoli na naslov iz telesa in nikoli
    // anonimnemu klicatelju (#275 S1): sicer je pot rele za ribarjenje pod domeno outly.si in izcrpa dnevno kvoto Resenda.
    if (!p.potrdiloNa) return;
    const r2 = await resend.emails.send({
      from, to: p.potrdiloNa,
      subject: "We received your application",
      html: nogaMaila({ html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – application received</h2>
      <p>Thanks for applying to bring <b>${ubeziHtml(p.businessName)}</b> to ${appName}.</p>
      <p>A real person reads every application. If we need documents — business licence, proof of ownership, tax number or bank details — we will ask for them in our reply. Please don't send them before we ask.</p>
      <p>We'll get back to you at this address.</p>
    </div>` }).html,
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
    console.log("Nova prošnja ustvarjalca:", r.rows[0].id);   // brez imena podjetja in e-naslova (osebni podatek, N1 17. 10. 2026)
    posljiMailProsnja({
      id: r.rows[0].id, userId: req.user ? req.user.userId : null, potrdiloNa: req.user ? email : null, businessName, contactName, email, phone: phoneRaw,
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
        (SELECT COUNT(*)::int FROM events WHERE status='published' AND start_at > NOW()) AS upcoming_events,
        (SELECT COUNT(*)::int FROM reports WHERE status='open')              AS open_reports,
        (SELECT COUNT(*)::int FROM vracila WHERE stanje IN ('ni_uspelo','rocno')) AS refunds_attention,
        (SELECT COUNT(*)::int FROM spori WHERE zaprt_at IS NULL)             AS open_disputes,
        (SELECT COUNT(*)::int FROM spori WHERE povrnitev_stanje IN ('ni_uspelo','rocno')) AS dispute_recovery_attention`);
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
      `SELECT ${adminStolpciKluba()},
              (SELECT COUNT(*)::int FROM events e WHERE e.club_id = c.id) AS event_count
       FROM clubs c LEFT JOIN users u ON u.id = c.owner_user_id
       ${kje} ORDER BY c.created_at DESC LIMIT 500`, p
    );
    return res.json(r.rows.map(dodajSellerComplete));   // seller_complete: oznaka »podatki prodajalca manjkajo« v panelu (043)
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

function poljaKluba(b, zaVstavljanje, stare) {
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
  // URL polja (#269): samo http(s) (razclenjen URL), website/instagram brez sheme dobita https://. `stare` = trenutni zapis (PATCH): nespremenjena
  // vrednost se ne preverja, ker admin panel ob shranjevanju poslje cel obrazec. Napaka `url` je JSON { error: "invalid_url", field, message }.
  const urlA = preveriUrlPolja([["logo_url", out.logo_url], ["banner_url", out.banner_url], ["website", out.website, { normaliziraj: true }],
    ["instagram", out.instagram, { normaliziraj: true, instagram: true }]], stare);
  if (urlA.napaka) return { napaka: urlA.napaka.message, url: urlA.napaka };
  Object.assign(out, urlA.vrednosti);
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
  // Organizator brez prizorisca in uradni profil Outly (037). is_official in is_demo (050) se nastavita SAMO tu (admin pot); PATCH /business/clubs/me ju ne sprejme.
  for (const [kljuc, ...imena] of [["is_organizer", "isOrganizer", "is_organizer"], ["is_official", "isOfficial", "is_official"], ["is_demo", "isDemo", "is_demo"]]) {
    const ime = imena.find(i => b[i] !== undefined);
    if (ime === undefined) continue;
    if (typeof b[ime] !== "boolean") return { napaka: `${imena[0]} must be true or false.` };
    out[kljuc] = b[ime];
  }
  // Podatki prodajalca (043, #94): admin sme vedno; isti pravili kot PATCH /business/clubs/me.
  const pp = preveriPodatkeProdajalca(b);
  if (pp.napaka) return { napaka: pp.napaka };
  Object.assign(out, pp.polja);
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

// I50: stikalo `is_official` preusmeri VES denar prodaje kluba na platformni racun (provizije ni, klub ne dobi denarja): vsaka SPREMEMBA (staro -> novo) gre v dnevnik
// (kdo, kateri klub), da je za nazaj razvidno, od kdaj prodaja kluba ni vec njegova. Brez e-naslova klubov, samo id-ji.
function zapisiSpremembaUradnega(req, klubId, ime, staro, novo) {
  const a = staro === true, n = novo === true;
  if (a === n) return;
  const kdo = req.user && req.user.userId ? `admin uporabnik ${req.user.userId}` : "admin (neznan)";
  console.warn(`[admin] POZOR is_official: ${kdo} je klubu ${klubId} (${String(ime).slice(0, 80)}) spremenil is_official ${a} -> ${n}; ${n ? "NOVE prodaje kluba gredo na racun NEXT DIMENSIONS brez provizije, klub ne dobi denarja" : "nove prodaje kluba spet po Connectu (obstojeca narocila ostanejo platformna)"}`);
}

admin.post("/clubs", async (req, res) => {
  const b = req.body || {};
  const c = await pool.connect();
  try {
    if (b.ownerEmail === undefined && b.owner_email === undefined) return res.status(400).send("ownerEmail is required.");
    const pk = poljaKluba(b, true);
    if (pk.napaka) return pk.url ? res.status(400).json(pk.url) : res.status(400).send(pk.napaka);
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
      `SELECT ${adminStolpciKluba()}, 0 AS event_count FROM clubs c LEFT JOIN users u ON u.id=c.owner_user_id WHERE c.id=$1`,
      [r.rows[0].id]
    );
    await c.query("COMMIT");
    zapisiSpremembaUradnega(req, r.rows[0].id, nov.rows[0].name, false, nov.rows[0].is_official);
    return res.status(201).json(dodajSellerComplete(nov.rows[0]));
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
    const stareUrl = (await c.query("SELECT logo_url, banner_url, website, instagram FROM clubs WHERE id=$1", [id])).rows[0];   // nespremenjen stari zapis se ne preverja (#269)
    const pk = poljaKluba(b, false, stareUrl);
    if (pk.napaka) return pk.url ? res.status(400).json(pk.url) : res.status(400).send(pk.napaka);
    const prov = provizijaIzTelesa(b);
    if (prov && prov.napaka) return res.status(400).send(prov.napaka);
    if (prov) pk.polja.commission_bps = prov.bps;
    const polja = pk.polja;

    await c.query("BEGIN");
    const obstaja = await c.query("SELECT id, name, owner_user_id, is_official FROM clubs WHERE id=$1 FOR UPDATE", [id]);
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
      `SELECT ${adminStolpciKluba()}, (SELECT COUNT(*)::int FROM events e WHERE e.club_id=c.id) AS event_count
       FROM clubs c LEFT JOIN users u ON u.id=c.owner_user_id WHERE c.id=$1`, [id]
    );
    await c.query("COMMIT");
    zapisiSpremembaUradnega(req, id, obstaja.rows[0].name, obstaja.rows[0].is_official, r.rows[0].is_official);
    return res.status(200).json(dodajSellerComplete(r.rows[0]));
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

// Testno naročilo (alias `o`), glej komentar »TESTNI PROMET (#230)« pri GET /admin/api/finance. Uporabljajo: /finance, /admin/api/events (#236), GET /business/sales (#236).
const SQL_TESTNO_NAROCILO = `(COALESCE(o.stripe_payment_intent_id LIKE 'test\\_%', FALSE) OR COALESCE(o.stripe_checkout_session_id LIKE 'cs\\_test\\_%', FALSE))`;
const SQL_PRAVO_NAROCILO = `NOT ${SQL_TESTNO_NAROCILO}`;
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
              e.ticket_url, e.created_at, e.capacity, e.sold_count, e.sales_paused, e.sales_open_at, e.sales_close_at, e.vip_enabled, ${PRIZORISCE_E},
              -- #190: koliko placanih narocil (brez guest liste) bi odpoved vrnila kupcem; admin panel to pokaze v potrditvenem oknu pred »Umakni«
              -- #236: paid_orders/paid_cents = samo PRAVI promet; testna (lazni nacin, Stripe sandbox) locena v test_paid_*; odpoved vrne vsa placana narocila (panel pokaze oboje)
              (SELECT COUNT(*)::int FROM orders o WHERE o.event_id = e.id AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_PRAVO_NAROCILO}) AS paid_orders,
              (SELECT COALESCE(SUM(o.total_cents - o.refunded_cents), 0)::int FROM orders o WHERE o.event_id = e.id AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_PRAVO_NAROCILO}) AS paid_cents,
              (SELECT COUNT(*)::int FROM orders o WHERE o.event_id = e.id AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_TESTNO_NAROCILO}) AS test_paid_orders,
              (SELECT COALESCE(SUM(o.total_cents - o.refunded_cents), 0)::int FROM orders o WHERE o.event_id = e.id AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_TESTNO_NAROCILO}) AS test_paid_cents
       FROM events e JOIN clubs c ON c.id = e.club_id ${PRIZORISCE_JOIN}
       ${kje} ORDER BY e.start_at DESC LIMIT 500`, p
    );
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Umik dogodka: status -> cancelled. Ne briše: če bodo kdaj prodane vstopnice,
// so naročila računovodski dokument (glej DELETE /events/:id).
// Odpoved gre prek sprozilca events_odpoved + sweep vracil (I37). Od faze 1 panela (055, I53): zapis v admin_dejanja v ISTI transakciji, zaklep vrstice
// (FOR NO KEY UPDATE: hkratni PATCH istega dogodka pocaka), objava obvesti sledilce kot PATCH /events/:id (U1; prej jih panel ni obvestil).
// Neobvezen `reason` (do 500 znakov) gre v dnevnik.
admin.patch("/events/:id", async (req, res) => {
  const id = celoId4(req.params.id);
  if (!id) return res.status(400).send("Invalid event id.");
  const b = req.body || {};
  const status = b.status;
  if (!["draft", "published", "cancelled"].includes(status)) return res.status(400).send("status must be draft, published or cancelled.");
  const razlog = b.reason === undefined || b.reason === null ? null : String(b.reason).trim().slice(0, 500) || null;
  const c = await pool.connect();
  let r, star;
  try {
    await c.query("BEGIN");
    star = (await c.query("SELECT id, club_id, status FROM events WHERE id = $1 FOR NO KEY UPDATE", [id])).rows[0];
    if (!star) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    r = await c.query(
      `UPDATE events SET status=$2 WHERE id=$1
       RETURNING id, club_id, title, start_at, status`, [id, status]
    );
    if (star.status !== status) {
      await zapisiAdminDejanje(c, req, dejanjeDogodka({ status: star.status }, { status }), "event", id, { status: star.status }, { status }, razlog);
    }
    await c.query("COMMIT");
  } catch (e) { await c.query("ROLLBACK").catch(() => {}); console.error(e); return res.status(500).send("Server error."); }
  finally { c.release(); }
  razprodanoPozabi("v:" + id);
  console.log(`Admin ${req.user.userId} dogodek ${id} -> ${status}`);
  if (star.status !== "published" && status === "published") {
    try { await obvestiSledilce(id, star.club_id); }
    catch (e) { console.error("Obvescanje sledilcev ni uspelo:", e.message); }
  }
  return res.status(200).json(r.rows[0]);
});

// GET /admin/api/events/:id — vsa urejljiva polja dogodka (za urejevalnik v panelu) + stevci + zadnjih 30 vrstic dnevnika (055, I53).
// Samo branje v READ ONLY transakciji s casovno mejo (glavni pool nima statement_timeout); vse po indeksih (orders_event_idx, tickets_event_idx, admin_dejanja_cilj_idx).
// Brez osebnih podatkov kupcev (samo stevila); dnevnik ima e-naslov ADMINA, ki je dejanje naredil (ne kupca).
admin.get("/events/:id", async (req, res) => {
  const id = celoId4(req.params.id);
  if (!id) return res.status(400).send("Invalid event id.");
  const c = await pool.connect();
  try {
    await c.query("BEGIN READ ONLY");
    await c.query("SET LOCAL statement_timeout = 3000");
    const er = await c.query(
      `SELECT e.id, e.club_id, cl.name AS club_name, cl.hidden AS club_hidden, cl.is_demo AS club_is_demo, e.title, e.description, e.poster_url,
              e.start_at, e.end_at, e.min_age, e.genres, e.status, e.ticket_price_cents, e.currency, e.ticket_url, e.capacity, e.sold_count,
              e.sales_paused, e.sales_open_at, e.sales_close_at, e.vip_enabled, e.recap_video_url, e.created_at,
              e.venue_club_id, e.venue_name, e.venue_address, e.venue_city, e.venue_lat, e.venue_lng
         FROM events e JOIN clubs cl ON cl.id = e.club_id WHERE e.id = $1`, [id]);
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    const st = (await c.query(
      `SELECT (SELECT COUNT(*)::int FROM orders o WHERE o.event_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_PRAVO_NAROCILO}) AS paid_orders,
              (SELECT COALESCE(SUM(o.total_cents - o.refunded_cents), 0)::int FROM orders o WHERE o.event_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_PRAVO_NAROCILO}) AS paid_cents,
              (SELECT COUNT(*)::int FROM orders o WHERE o.event_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_TESTNO_NAROCILO}) AS test_paid_orders,
              (SELECT COALESCE(SUM(o.total_cents - o.refunded_cents), 0)::int FROM orders o WHERE o.event_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_TESTNO_NAROCILO}) AS test_paid_cents,
              (SELECT COUNT(*)::int FROM orders o WHERE o.event_id = $1 AND o.status = 'pending') AS pending_orders,
              (SELECT COUNT(*)::int FROM tickets t WHERE t.event_id = $1 AND t.status = 'used') AS checked_in`, [id])).rows[0];
    const dn = await c.query(
      `SELECT a.id, a.cas, a.dejanje, a.prej, a.potem, a.razlog, u.email AS admin_email
         FROM admin_dejanja a LEFT JOIN users u ON u.id = a.admin_user_id
        WHERE a.cilj_tip = 'event' AND a.cilj_id = $1 ORDER BY a.cas DESC, a.id DESC LIMIT 30`, [String(id)]);
    await c.query("COMMIT");
    return res.json({ event: er.rows[0], stats: st, audit: dn.rows });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    console.error(e); return res.status(500).send("Server error.");
  } finally { c.release(); }
});

// GET /admin/api/audit?target_type=event&target_id=35&limit=50 — dnevnik admin dejanj (055, I53), najnovejse najprej. Brez filtra vse (najvec 200).
admin.get("/audit", async (req, res) => {
  try {
    const p = [], pogoji = [];
    const tip = req.query.target_type, cilj = req.query.target_id;
    if (tip !== undefined) {
      if (typeof tip !== "string" || !/^[a-z_]{1,30}$/.test(tip)) return res.status(400).send("Invalid target_type.");
      p.push(tip); pogoji.push(`a.cilj_tip = $${p.length}`);
    }
    if (cilj !== undefined) {
      if (typeof cilj !== "string" || !/^[\w-]{1,60}$/.test(cilj)) return res.status(400).send("Invalid target_id.");
      p.push(cilj); pogoji.push(`a.cilj_id = $${p.length}`);
    }
    const lim = Math.min(200, Math.max(1, celoId(req.query.limit) || 50));
    p.push(lim);
    const r = await pool.query(
      `SELECT a.id, a.cas, a.dejanje, a.cilj_tip AS target_type, a.cilj_id AS target_id, a.prej, a.potem, a.razlog, u.email AS admin_email
         FROM admin_dejanja a LEFT JOIN users u ON u.id = a.admin_user_id
        ${pogoji.length ? "WHERE " + pogoji.join(" AND ") : ""} ORDER BY a.cas DESC, a.id DESC LIMIT $${p.length}`, p);
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- vracila in spori (#190, migracija 047) ---
// GET /admin/api/refunds?state=ni_uspelo|rocno|potrditev|caka|v_teku|opravljeno|preklicano&event_id=&limit= : vrsta vracil (brez e-naslovov kupcev). `attention` = vracila, ki so
// ostala brez denarja za kupca (ni_uspelo, rocno) ali visijo (v_teku): jih je treba pogledati. Tudi v dnevniku: `[vracila] POZOR`.
// `not_completed_mail_sent_at` (#251) = kdaj je kupec dobil mail `ni_izvedeno` (Stripe je vracilo zavrnil, uredimo rocno), sicer null.
// `stripe_state` = Stripovo stanje vracila (pending|succeeded|failed|canceled|…, lahko null). `failed`/`canceled`: retry je zavrnjen (409, vracilo.ponovi), panel gumba ne ponuja. `requires_action` NI zavrnitev (kupec dobi navodila, vracilo se nadaljuje): vrstica je v `potrditev` kot pri pending.
admin.get("/refunds", async (req, res) => {
  try {
    const STANJA = ["caka", "v_teku", "potrditev", "opravljeno", "ni_uspelo", "rocno", "preklicano"];
    const stanje = req.query.state === undefined ? null : String(req.query.state);
    if (stanje !== null && !STANJA.includes(stanje)) return res.status(400).send("state must be one of: " + STANJA.join(", ") + ".");
    const ev = req.query.event_id === undefined ? null : celoId4(req.query.event_id);
    if (req.query.event_id !== undefined && ev === null) return res.status(400).send("Invalid event_id.");
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 200);
    const stevila = await pool.query("SELECT stanje, COUNT(*)::int AS n FROM vracila GROUP BY stanje");
    const counts = Object.fromEntries(STANJA.map((x) => [x, 0]));
    for (const x of stevila.rows) counts[x.stanje] = x.n;
    const r = await pool.query(
      `SELECT v.id, v.order_id, o.public_ref, v.event_id, e.title AS event_title, v.razlog AS reason, v.stanje AS state, v.znesek_cents AS amount_cents, o.currency, COALESCE(v.valuta, o.currency) AS currency_paid,
              v.poskusi AS attempts, v.napaka AS error, v.brez_stripa AS no_stripe, v.stripe_vracilo_id AS stripe_refund_id,
              v.provizija_za_vrnitev_cents AS fee_refund_cents, v.provizija_vracilo_id AS stripe_fee_refund_id, v.stripe_pristojbina_cents AS stripe_fee_cents,
              v.stripe_stanje AS stripe_state, v.created_at, v.naslednji_poskus_at AS next_attempt_at, v.opravljeno_at AS done_at, v.mail_poslano_at AS mail_sent_at,
              v.mail_ni_izvedeno_poslano_at AS not_completed_mail_sent_at
         FROM vracila v JOIN orders o ON o.id = v.order_id JOIN events e ON e.id = v.event_id
        WHERE ($1::text IS NULL OR v.stanje = $1) AND ($2::int IS NULL OR v.event_id = $2)
        ORDER BY v.id DESC LIMIT $3`, [stanje, ev, limit]);
    return res.json({ counts, attention: counts.ni_uspelo + counts.rocno, items: r.rows });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});
// POST /admin/api/refunds/:id/retry : vracilo v stanju ni_uspelo / rocno znova v vrsto (po odpravi vzroka). Idempotentni Stripov kljuc prepreci dvojno vracilo.
admin.post("/refunds/:id/retry", async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id || id > 9007199254740991) return res.status(400).send("Invalid refund id.");
    if (!(await vracilaStripe.ponovi(id))) return res.status(409).send("Only a refund in state ni_uspelo or rocno can be retried.");
    console.log(`Admin ${req.user.userId} je ponovno vrinil vracilo ${id} v vrsto`);
    return res.json({ id, state: "caka" });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});
// GET /admin/api/disputes?open=1&limit= : Stripovi spori (chargeback) + stanje povrnitve od kluba ob izgubljenem sporu (recovery_*).
// POST /admin/api/disputes/:id/retry : povrnitev (transfer reversal) v stanju ni_uspelo / rocno znova v vrsto.
admin.get("/disputes", async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 200);
    const odprti = req.query.open === "1" || req.query.open === "true";
    const r = await pool.query(
      `SELECT s.id, s.order_id, o.public_ref, e.title AS event_title, e.club_id, s.stanje AS state, s.razlog AS reason, s.znesek_cents AS amount_cents, s.valuta AS currency,
              s.rok_dokazov_at AS evidence_due_at, s.ustvarjen_at AS created_at, s.zaprt_at AS closed_at, s.mail_odprt_poslano_at AS opened_mail_sent_at, s.mail_zaprt_poslano_at AS closed_mail_sent_at,
              s.povrnitev_stanje AS recovery_state, s.povrnitev_zelena_cents AS recovery_wanted_cents, s.povrnitev_cents AS recovered_cents, s.pristojbina_spora_cents AS dispute_fee_cents,
              s.reversal_id AS stripe_reversal_id, s.povrnitev_napaka AS recovery_error,
              CASE WHEN s.order_id IS NULL THEN NULL ELSE o.status IN ('paid', 'partially_refunded', 'refunded') END AS order_paid
         FROM spori s LEFT JOIN orders o ON o.id = s.order_id LEFT JOIN events e ON e.id = o.event_id
        WHERE ($1::boolean = FALSE OR s.zaprt_at IS NULL) ORDER BY s.ustvarjen_at DESC LIMIT $2`, [odprti, limit]);
    return res.json({ items: r.rows });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

admin.post("/disputes/:id/retry", async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!/^dp_[A-Za-z0-9]{1,60}$/.test(id)) return res.status(400).send("Invalid dispute id.");
    const pon = await vracilaStripe.ponoviSpor(id);
    if (pon === "neplacano") return res.status(409).json({ error: "dispute_unpaid_order", message: "Dispute on an unpaid/cancelled order: recovery from the club is not allowed without Martin's decision (state stays rocno)." });
    if (!pon) return res.status(409).send("Only a recovery in state ni_uspelo or rocno can be retried.");
    console.log(`Admin ${req.user.userId} je ponovno vrinil povrnitev spora ${id} v vrsto`);
    return res.json({ id, recovery_state: "caka" });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- finance ---
// GET /admin/api/finance?from=YYYY-MM-DD&to=YYYY-MM-DD
// Promet celotne platforme za admin panel: skupaj, po klubih, po dogodkih,
// po dnevih, zadnja naročila. Zneski v centih, EUR. "Prihodek Outlyja" =
// application_fee_cents (provizija PROVIZIJA_ODSTOTEK); "za klube" = bruto
// minus provizija minus vračila. Štejejo se plačana naročila (paid, partially_refunded) in od #310 (20. 10. 2026) tudi v CELOTI
// vrnjena (refunded): ta so v `gross_cents`, `refunded_cents` in `orders` (+ novo `refunded_orders`), `buyers`, `clubs_with_sales`,
// NISO pa v `fee_cents` in `tickets_sold`/`tickets` (vstopnice ne veljajo, provizija se ob odpovedi vrne klubu), zato neto (`clubs_net_cents`,
// `net_cents`, `own_sales_cents`) ostane bruto − provizija − vračila in je za vrnjeno naročilo 0, kot pred #310. Velja za summary, all_time, by_club,
// by_event, by_day in testni promet (test_summary, all_time_test). Stripova pristojbina vrnjenega plačila (je Stripe ne vrne) NI v bazi in je ni v poročilu.
// I50: prodaja uradnega profila Outly (prodajalec je platforma, SQL_NAROCILO_PLATFORMNO: plačilo neposredno na platformni račun, provizija 0) je bruto
// prodaja (vsa je prihodek Outlyja), v "za klube" / net_cents je NI (nobenemu klubu ni dolgovana); DODANO polje `own_sales_cents` = bruto - vračila te prodaje
// (summary, by_club).
//
// TESTNI PROMET (#230): summary, all_time, by_club, by_event in by_day so SAMO PRAVI promet; testni je ločen
// (test_summary, all_time_test, summary.test_orders). Testno naročilo (SQL_TESTNO_NAROCILO) je
//   * `stripe_payment_intent_id LIKE 'test_%'`  - lažni način brez Stripa (backend sam zapiše test_<uuid>), ali
//   * `stripe_checkout_session_id LIKE 'cs_test_%'` - Stripe SANDBOX (seja cs_test_, PaymentIntent pi_... je enak kot v živem, zato ga po njem ni mogoče ločiti).
// Plačilo prek Stripa vedno gre skozi Checkout sejo (zakljuci() v placila_stripe.js zapiše sejo ob prehodu v paid), zato druge poti do sandbox naročila brez seje ni.
// Brezplačno (0 EUR) naročilo brez Stripa (pi NULL, seja NULL) je PRAVO naročilo (brezplačne vstopnice, prava vstopnica in obveznost), le brez denarja;
// 0 EUR naročilo v lažnem načinu ima test_ in je zato testno. is_test v recent_orders ima to definicijo, NE pomena iz STOLPCI_NAROCILA (tam is_test = lažni način
// brez plačila in vodi vedenje nakupa: sandbox naročilo je šlo skozi Stripe, ima checkout_url in prave maile).
// (SQL_TESTNO_NAROCILO in SQL_PRAVO_NAROCILO sta definirana pred admin GET /events; razlaga definicije je v komentarju pri /finance.)
admin.get("/finance", async (req, res) => {
  try {
    const dan = (v) => (typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v)) ? v : null;
    const do_ = dan(req.query.to) || new Date().toISOString().slice(0, 10);
    const od = dan(req.query.from) || new Date(Date.now() - 29 * 864e5).toISOString().slice(0, 10);
    if (od > do_) return res.status(400).send("from must be before to.");
    // Meji sta datuma; zgornja je vključujoča (do konca dneva).
    const p = [od, do_];
    // o.guest_list_id IS NULL: guest lista (035, I24) ni prodaja (brez zneska); ne sme v stevilo narocil, kupcev, vstopnic.
    // #310: v celoti vrnjena naročila (`refunded`) so del prometa (bruto in vračila), sicer bi iz poročila izginila (bruto 0, vračilo 0).
    const STANJA = `o.status IN ('paid','partially_refunded','refunded')`;
    const NETO = `o.status <> 'refunded'`;   // provizija in vstopnice: samo naročila, ki niso v celoti vrnjena (neto ostane bruto − provizija − vračila kot prej)
    const KJE_VSE = `${STANJA} AND o.guest_list_id IS NULL AND o.created_at >= $1::date AND o.created_at < ($2::date + INTERVAL '1 day')`;
    const KJE = `${KJE_VSE} AND ${SQL_PRAVO_NAROCILO}`;   // pravi promet (brez lažnega načina in sandboxa)
    const PLATFORMNO = placilaStripe.SQL_NAROCILO_PLATFORMNO("o");   // I50: prodajalec je platforma (uradni profil Outly)
    const SESTEVEK_TEST = `COUNT(*)::int AS orders,
                COUNT(*) FILTER (WHERE o.status = 'refunded')::int AS refunded_orders,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets_sold`;

    const [skupaj, poKlubih, poDogodkih, poDnevih, zadnja, vseh, testObdobje, testVseh] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents) FILTER (WHERE NOT ${PLATFORMNO} AND ${NETO}),0)::int AS clubs_net_cents,
                COALESCE(SUM(o.total_cents - o.refunded_cents) FILTER (WHERE ${PLATFORMNO}),0)::int AS own_sales_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets_sold,
                COUNT(*)::int AS orders,
                COUNT(*) FILTER (WHERE o.status = 'refunded')::int AS refunded_orders,
                COUNT(DISTINCT COALESCE(o.user_id::text, lower(o.guest_email)))::int AS buyers,
                COUNT(DISTINCT o.club_id)::int AS clubs_with_sales
         FROM orders o WHERE ${KJE}`, p),
      pool.query(
        `SELECT c.id, c.name, c.city, ${sqlStripeStanje("c.")},
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents) FILTER (WHERE NOT ${PLATFORMNO} AND ${NETO}),0)::int AS net_cents,
                COALESCE(SUM(o.total_cents - o.refunded_cents) FILTER (WHERE ${PLATFORMNO}),0)::int AS own_sales_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets_sold,
                COUNT(o.id)::int AS orders,
                COUNT(o.id) FILTER (WHERE o.status = 'refunded')::int AS refunded_orders
         FROM clubs c LEFT JOIN orders o ON o.club_id = c.id AND ${KJE}
         GROUP BY c.id ORDER BY gross_cents DESC, c.name`, p),
      pool.query(
        `SELECT e.id, e.title, e.start_at, e.status, e.ticket_price_cents, e.capacity, e.sold_count,
                c.name AS club_name,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COUNT(o.id)::int AS orders,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets_sold,
                (SELECT COUNT(*)::int FROM tickets t WHERE t.event_id = e.id AND t.status = 'used') AS checked_in
         FROM events e JOIN clubs c ON c.id = e.club_id
         LEFT JOIN orders o ON o.event_id = e.id AND ${KJE}
         GROUP BY e.id, c.name HAVING COUNT(o.id) > 0
         ORDER BY gross_cents DESC LIMIT 50`, p),
      pool.query(
        `SELECT to_char(d.dan, 'YYYY-MM-DD') AS day,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets,
                COUNT(o.id)::int AS orders
         FROM generate_series($1::date, $2::date, '1 day') AS d(dan)
         LEFT JOIN orders o ON ${STANJA} AND o.guest_list_id IS NULL AND ${SQL_PRAVO_NAROCILO}
              AND o.created_at >= d.dan AND o.created_at < d.dan + INTERVAL '1 day'
         GROUP BY d.dan ORDER BY d.dan`, p),
      pool.query(
        `SELECT ${STOLPCI_NAROCILA}, ${SQL_TESTNO_NAROCILO} AS testni_promet, e.title AS event_title, c.name AS club_name, COALESCE(u.username, ${IME_GOSTA}) AS buyer_username
         FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs c ON c.id = o.club_id
         LEFT JOIN users u ON u.id = o.user_id
         WHERE o.created_at >= $1::date AND o.created_at < ($2::date + INTERVAL '1 day') AND o.guest_list_id IS NULL
         ORDER BY o.created_at DESC LIMIT 100`, p),
      pool.query(
        `SELECT COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets_sold, COUNT(*)::int AS orders,
                COUNT(*) FILTER (WHERE o.status = 'refunded')::int AS refunded_orders
         FROM orders o WHERE ${STANJA} AND o.guest_list_id IS NULL AND ${SQL_PRAVO_NAROCILO}`),
      pool.query(`SELECT ${SESTEVEK_TEST} FROM orders o WHERE ${KJE_VSE} AND ${SQL_TESTNO_NAROCILO}`, p),
      pool.query(`SELECT ${SESTEVEK_TEST} FROM orders o WHERE ${STANJA} AND o.guest_list_id IS NULL AND ${SQL_TESTNO_NAROCILO}`),
    ]);
    return res.json({
      mode: testniNacinPlacil() ? "test" : "live",   // "live" je tudi ob sandbox kljucu (sk_test_): za panel glej payments_mode
      // payments_mode (#230): "fake" = brez Stripa / TEST_PLACILA (vstopnice brez placila), "sandbox" = Stripe sk_test_ (ni pravi denar), "live" = sk_live_.
      payments_mode: placilaStripe.testniNacin() ? "fake" : (placilaStripe.jeSandbox() ? "sandbox" : "live"),
      fee_percent: PROVIZIJA_ODSTOTEK,
      from: od, to: do_,
      summary: { ...skupaj.rows[0], test_orders: testObdobje.rows[0].orders },   // test_orders: staro polje, zdaj po novi definiciji
      all_time: vseh.rows[0],
      test_summary: testObdobje.rows[0],       // testni promet v obdobju (ni pravi denar)
      all_time_test: testVseh.rows[0],
      by_club: poKlubih.rows,
      by_event: poDogodkih.rows,
      by_day: poDnevih.rows,
      recent_orders: zadnja.rows.map(({ testni_promet, ...o }) => ({ ...o, is_test: testni_promet })),   // is_test: nova definicija (glej SQL_TESTNO_NAROCILO)
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

// Testni nacin za ves sistem (dashboard `mode`): TEST_PLACILA ima ucinek samo brez kljuca / ob sandbox kljucu, ob sk_live_ je ignoriran (#191, placila_stripe.js).
function testniNacinPlacil() {
  return placilaStripe.testniNacin();
}

// ---------------------------
// STRIPE (issue #19): Checkout + Connect Express. Logika je v placila_stripe.js; tu so poti.
// ---------------------------
const placilaStripe = require("./placila_stripe");
// Pavza prodaje (055, I53): prekinitev odprtih placilnih oken dogodka po COMMIT-u (PATCH /events/:id).
const pavzaProdaje = require("./pavza_prodaje");
const pavzaOkna = pavzaProdaje.ustvari({ pool, stripe: placilaStripe.stripe, jeLive: placilaStripe.jeLive, razprodanoPozabi: (id) => razprodanoPozabi("v:" + id) });
// naPlacano: po COMMIT-u webhooka/pospravljalca poslje mail: gostu z vstopnicami (nakup brez racuna, migracija 033) ALI kupcu z racunom potrdilo (042, #95).
// Vsaka od obeh poti sama preveri, ali je narocilo njeno (user_id NULL + guest_email / user_id + receipt_mail_attempts), druga ne stori nicesar.
// naSporu: po COMMIT-u webhooka charge.dispute.* obvesti lastnika kluba (mail; #190). Samo stanje in obvestilo: denarja ne premika, vstopnice ne razveljavi.
const stripePlacila = placilaStripe.ustvari({ pool, naPlacano: (id) => Promise.all([posljiGostuVstopnice(id), posljiPotrdiloKupcu(id)]), naSporu: (id) => posljiSporLastniku(id), naVracilu: (re) => vracilaStripe.uskladiVracilo(re), naVraciluIzStripa: (ch) => posljiVracilaIzStripaNaboja(ch) });
stripePlacila.zazeni();
// Vracila (#190, vracila_stripe.js): odpoved dogodka -> vrsta `vracila`, obdelovalec v ozadju (ne v zahtevku). posljiNeposlane: obvestila kupcem in lastnikom klubov (po vrsti, razmik za Resend).
const vracilaStripe = require("./vracila_stripe").ustvari({ pool, posljiNeposlane: () => vracilaObvestilaNeposlana() });
vracilaStripe.zazeni();
// Davcno potrjeni racuni lastnih dogodkov Outly (I52, migracija 054): delavec v ozadju na glavnem poolu (nikoli skenPool). Privzeto RACUNI_PONUDNIK izklopljen:
// dolg racuna se zapise (zakljuci, uveljaviVracilo), stevilk in klicev ni. Potrdilo kupcu (I32) se v tem koraku NE spremeni.
require("./racuni").ustvari({ pool }).zazeni();
app.post("/stripe/webhook", express.raw({ type: "*/*", limit: "1mb" }), stripePlacila.webhook);

// Klub, za katerega gre (requireClub). Admin brez izbranega kluba ga mora izbrati (glava X-Outly-Club).
async function stripeKlub(req, res) {
  if (!req.klub || !req.klub.clubId) { res.status(400).send("Choose a club."); return null; }
  const r = await pool.query("SELECT id, name, stripe_account_id, stripe_charges_enabled, stripe_payouts_enabled, stripe_account_livemode FROM clubs WHERE id=$1", [req.klub.clubId]);
  if (!r.rows.length) { res.status(404).send("Club not found."); return null; }
  const k = r.rows[0];
  // I36 (#227): racun iz drugega nacina (sandbox racun ob sk_live_) je za ta nacin NEPOVEZAN: brez klica Stripa na tuj racun
  // (accounts.retrieve / createLoginLink bi padla), onboarding naredi nov racun (stripeRacunKluba).
  if (k.stripe_account_id && !placilaStripe.racunVNacinu(k)) {
    k.stripe_account_id = null; k.stripe_charges_enabled = false; k.stripe_payouts_enabled = false;
  }
  return k;
}
function stripeNapaka(res, e, kaj) {
  console.error(`[stripe] ${kaj}:`, e && (e.message || e));
  return res.status(502).send("Payment provider error. Please try again.");
}

// Express racun kluba: ustvari ga najvec enkrat. Hkratna klika serializira zaklep na klub (velja med instancami), drugi
// po zaklepu vidi racun prvega. NAMENOMA brez Stripovega idempotentnega kljuca: Stripe si pod kljucem 24 h zapomni tudi
// ZAVRNITEV (3. 10. 2026: politika "Accounts v1" je bila izklopljena, po vklopu je isti kljuc se naprej vracal napako).
// I36 (#227): obstojec racun se ohrani samo, ce je iz TEKOCEGA nacina (`racunVNacinu`). Racun iz drugega nacina (sandbox racun ob sk_live_) se NADOMESTI
// z novim (id, `stripe_account_livemode = jeLive()`, charges/payouts false, onboarding znova), pod istim zaklepom. Obratno (ziv racun, sandbox kljuc) racuna
// NE prepisemo: izgubili bi povezavo z zivim racunom, zato napaka `stripe_live_account` (409). Ob ustvarjanju vedno zapisemo nacin.
async function stripeRacunKluba(s, k, userId) {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [`stripe-racun:${k.id}`]);
    const ze = (await c.query("SELECT stripe_account_id, stripe_account_livemode FROM clubs WHERE id=$1", [k.id])).rows[0];
    if (ze && ze.stripe_account_id && placilaStripe.racunVNacinu(ze)) { await c.query("COMMIT"); return ze.stripe_account_id; }
    if (ze && ze.stripe_account_id && ze.stripe_account_livemode === true) { const e = new Error("club has a live Stripe account"); e.koda = "stripe_live_account"; throw e; }
    const u = await c.query("SELECT email FROM users WHERE id=$1", [userId]);
    const nov = await s.accounts.create({
      type: "express",
      country: "SI",
      email: u.rows[0] ? u.rows[0].email : undefined,
      capabilities: { card_payments: { requested: true }, transfers: { requested: true } },
      business_profile: { name: k.name },
      metadata: { club_id: String(k.id) },
    });
    const ziv = placilaStripe.jeLive();
    await c.query(
      `UPDATE clubs SET stripe_account_id=$2, stripe_account_livemode=$3, stripe_charges_enabled=FALSE, stripe_payouts_enabled=FALSE, stripe_onboarded_at=NULL
        WHERE id=$1`, [k.id, nov.id, ziv]);
    await c.query("COMMIT");
    console.log(`[stripe] klub ${k.id}: nov Connect racun (${ziv ? "LIVE" : "sandbox"}${ze && ze.stripe_account_id ? ", nadomesca racun iz drugega nacina" : ""})`);
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
  } catch (e) {
    if (e && e.koda === "stripe_live_account") return res.status(409).send("This club is connected to a live Stripe account. Payments are in test mode right now.");
    return stripeNapaka(res, e, "onboarding");
  }
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
// Jezik Checkouta: neobvezno polje telesa `locale` ("sl" | "en", glej placilaStripe.normalizirajLocale); neveljavno = ni polja = Stripov auto, nikoli 400.
const localeNakupa = (req) => placilaStripe.normalizirajLocale(req.body && typeof req.body === "object" ? req.body.locale : undefined);
// Omejitev cakajocih (neplacanih) narocil (pregled 5. 10. 2026): cakajoce Stripe narocilo drzi zalogo ali mizo do ~35 min.
// Brez omejitve bi en racun z nekaj kliki zasedel razprodan dogodek ali vse VIP mize, ne da bi kaj placal.
// Pravilo: najvec 1 cakajoce narocilo na dogodek in najvec CAKAJOCA_NAJVEC skupaj na uporabnika. Kupec nedokoncano
// placilo nadaljuje prek checkout_url v GET /me/orders ali pocaka, da seja poteče (pospravljalec jo sprosti).
// Zaklep (uporabnik) v isti transakciji kot INSERT: dva hkratna nakupa istega uporabnika ne prideta mimo stetja oba.
// Ponovitev z istim Idempotency-Key se vrne prej (plast 3), zato je to pravilo ne zavrne.
const CAKAJOCA_NAJVEC = 3;
// Placila »v obdelavi« (odlozeno placilo: seja opravljena, denar na poti, checkout_url NULL ob seji) NE stejejo med nedokoncana (kupec je svoje opravil), imajo pa
// LASTNO mejo (pregled PR #203, 2. krog): brez nje bi en racun z nekaj odlozenimi placili (SEPA) in izgubljenim `async_payment_failed` drzal zalogo neomejeno.
// Ob preseganju 409, dokler banka ne potrdi (ali zavrne) kaksnega od njih.
const OBDELAVI_NAJVEC = 3;
const CAKAJOCA_ZAKLEP_RAZRED = 73110;   // prvi del dvodelnega advisory kljuca (drugi = id uporabnika); ne trci z migrate.js (enodelni kljuc)
async function omejitevCakajocih(c, userId, eventId) {
  await c.query("SELECT pg_advisory_xact_lock($1::int, $2::int)", [CAKAJOCA_ZAKLEP_RAZRED, userId]);
  const r = await c.query(
    `SELECT COUNT(*) FILTER (WHERE NOT obd)::int AS vse, COUNT(*) FILTER (WHERE NOT obd AND event_id = $2)::int AS ta, COUNT(*) FILTER (WHERE obd)::int AS obd
       FROM (SELECT event_id, (stripe_checkout_session_id IS NOT NULL AND checkout_url IS NULL) AS obd
               FROM orders WHERE user_id = $1 AND status = 'pending') x`, [userId, eventId]);
  const { vse, ta, obd } = r.rows[0];
  if (obd >= OBDELAVI_NAJVEC) return "You have too many payments still processing. Wait for your bank to confirm them.";
  if (ta > 0) return "You already have an unfinished payment for this event. Finish it in My tickets, or wait up to 30 minutes for it to expire.";
  if (vse >= CAKAJOCA_NAJVEC) return "You have too many unfinished payments. Finish one in My tickets, or wait up to 30 minutes for them to expire.";
  return null;
}

// Zgornja meja BREZPLACNIH vstopnic (0 EUR) na osebo in dogodek (#191, pregled PR #203): brez nje bi en racun (ali gost z mnogo naslovi) z nekaj kliki pobral vso
// zalogo prostega dogodka, ne da bi kaj placal in brez cakajocega narocila (I20 ne zajame). Oseba = uporabnik (user_id) ALI normaliziran e-naslov gosta
// (naslovKljuc: mala crka, brez »+oznake«, gmail brez pik). Enota = vstopnica; VIP miza za 0 EUR steje 1. Steje placano (paid / delno vrnjeno) brezplacno
// narocilo brez guest liste. Pod advisory zaklepom (uporabnik/naslov + dogodek): hkratna klica ne obideta meje. Meja ne ovira racuna, ki kupi kot gost z
// drugim naslovom (znana omejitev: ni zaščita pred odlocnim zlorabnikom, ta je omejen z IP omejevalnikom nakupov in kapaciteto dogodka).
// Vrne telo 409 { error: "free_limit", message } ali null.
const ZASTONJ_NA_OSEBO = okoljeCelo("ZASTONJ_NA_OSEBO", 10, 1, 1000);
// SQL enakovreden naslovKljuc (mala crka, brez »+oznake«, gmail/googlemail brez pik): st = izraz SQL z e-naslovom. Mora ostati v skladu z naslovKljuc().
const sqlNaslovKljuc = (st) => `(CASE WHEN split_part(lower(${st}), '@', 2) IN ('gmail.com','googlemail.com')
    THEN replace(split_part(split_part(lower(${st}), '@', 1), '+', 1), '.', '') || '@gmail.com'
    ELSE split_part(split_part(lower(${st}), '@', 1), '+', 1) || '@' || split_part(lower(${st}), '@', 2) END)`;
async function omejitevBrezplacnih(c, { userId = null, gostEmail = null, eventId, enot }) {
  let n;
  if (userId !== null) {
    await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [`zastonj:u:${userId}:${eventId}`]);
    n = (await c.query(
      `SELECT COALESCE(SUM(CASE WHEN table_id IS NOT NULL THEN 1 ELSE quantity END), 0)::int AS n FROM orders
        WHERE event_id = $1 AND user_id = $2 AND total_cents = 0 AND guest_list_id IS NULL AND status IN ('paid','partially_refunded')`, [eventId, userId])).rows[0].n;
  } else {
    const kljuc = naslovKljuc(gostEmail);
    await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [`zastonj:g:${kljuc}:${eventId}`]);
    n = (await c.query(
      `SELECT COALESCE(SUM(quantity), 0)::int AS n FROM orders o
        WHERE o.event_id = $1 AND o.guest_email IS NOT NULL AND o.total_cents = 0 AND o.status IN ('paid','partially_refunded')
          AND ${sqlNaslovKljuc("o.guest_email")} = $2`,
      [eventId, kljuc])).rows[0].n;
  }
  if (n + enot <= ZASTONJ_NA_OSEBO) return null;
  // Gostu NE povemo, koliko vstopnic ima naslov ze (brez prijave bi kdorkoli iz sporocila razbral, koliko jih ima tuj naslov); uporabnik vidi svoje.
  const ostane = Math.max(0, ZASTONJ_NA_OSEBO - n);
  return { error: "free_limit", message: `You can get at most ${ZASTONJ_NA_OSEBO} free tickets for this event${userId !== null && ostane > 0 ? ` (${ostane} left for you)` : ""}.` };
}

// Po COMMIT-u pending Stripe narocila: ustvari Checkout sejo in vrne telo odgovora (null = odgovor 502/503 je ze poslan).
// Dovoljenje nakupa in povezavo `d` sprosti TAKOJ (#274): od tu naprej `c` ni vec nas. Stripe tece pod lastnim semaforjem; zapis seje in branje
// odgovora pa na ENI kratkotrajni povezavi iz poola (drzimo eno povezavo in ne cakamo na drugo, zato pool ne zastane; glej opombo pri
// POST /events/:id/orders). Neuspeh Stripa, zapisa ali semaforja = narocilo `failed` (sprozilec sprosti zalogo).
async function nakupStripeSeja(res, d, { oid, opis, kolicina, cenaEnoteCents, racunKluba, platformno, email, eventId, odjemalec, povratna, locale }) {
  // Neuspeh: narocilo `failed` (sprozilec sprosti zalogo) in `idempotency_key = NULL`: neuspeh se ne zapomni (I18, test_idempotenca §6), sicer bi
  // ponovitev z istim kljucem dobila 409 order_not_active. Zapis ne sme tiho odpasti (narocilo bi ostalo `pending` brez seje ~35 min, I20): 2 poskusa + dnevnik.
  const neuspeh = async (db, koda, sporocilo) => {
    for (let poskus = 1; poskus <= 2; poskus++) {
      try {
        await db.query("UPDATE orders SET status='failed', cancelled_at=NOW(), idempotency_key=NULL WHERE id=$1 AND status='pending'", [oid]);
        break;
      } catch (e) {
        console.error(`[stripe] narocila ${oid} ni uspelo oznaciti kot failed (poskus ${poskus}):`, e && (e.message || e));
        db = pool;
      }
    }
    if (koda === 503) res.set("Retry-After", "5");
    res.status(koda).send(sporocilo);
    return null;
  };
  // Branje narocila na SE DRZANI povezavi, PRED sprostitvijo: po sprostitvi bi pool.query ob zasedenem poolu lahko padel in pustil narocilo brez seje.
  let nr;
  try {
    // Pavza prodaje (055, I53): PATCH, ki je prodajo ustavil med nasim branjem dogodka in tem trenutkom, je narocilo ze preklical (status ni vec `pending`)
    // ali pa je dogodek zdaj ustavljen: seje ne ustvarimo. Ostane le okno med tem branjem in zapisom seje (zapre ga pavza_prodaje.js, korak 2).
    nr = (await d.c.query(
      `SELECT o.id, o.public_ref, o.currency, o.application_fee_cents, o.status, e.sales_paused
         FROM orders o JOIN events e ON e.id = o.event_id WHERE o.id=$1`, [oid])).rows[0];
  } catch (e) {
    console.error(`[stripe] branje narocila ${oid} ni uspelo:`, e && (e.message || e));
    d.sprosti(e);   // pokvarjena povezava ne v pool; sele nato oznaka prek poola (brez drzanja ene in cakanja na drugo)
    return neuspeh(pool, 502, "Payment provider is unavailable. Please try again.");
  }
  d.sprosti();
  if (nr.status !== "pending" || nr.sales_paused === true) {
    console.log(`[pavza] narocilo ${nr.public_ref}: prodaja dogodka je bila ustavljena med nakupom, placilno okno ni odprto`);
    return neuspeh(pool, 409, NAPAKA_PAVZA_PRODAJE);
  }
  let c2 = null;
  try {
    if (!(await stripeVstopi())) {
      console.error(`[stripe] narocilo ${oid}: semafor za Stripe poln ${STRIPE_CAKANJE_MS} ms`);
      return await neuspeh(pool, 503, "Too many purchases at once. Please try again.");
    }
    let seja;
    try {
      seja = await placilaStripe.ustvariCheckout({ narocilo: nr, opis, kolicina, cenaEnoteCents, racunKluba, platformno, email, eventId, odjemalec, povratna, locale });
    } finally { stripeIzstopi(); }
    c2 = await pool.connect();
    let zapisano;
    try {
      // Samo cakajoce narocilo (055, I53): ce ga je pavza prodaje medtem preklicala, seje ne zapisemo in jo takoj zapremo (kupec ne dobi povezave).
      // M1 (pregled #316): pavza se preveri v ISTI izjavi kot zapis seje, v kratki transakciji z deljenim advisory zaklepom dogodka (kot pavzaPredCommitom):
      // pocaka na COMMIT hkratne pavze, nato UPDATE prebere svezo vrednost. Brez tega bi seja, zapisana tik po pavzi, ostala odprta
      // (ponovni korak pavze je samo v pomnilniku procesa). Zaklep pred vrstico narocila: pavza (ki preklice to narocilo) ne caka na nas.
      await c2.query("BEGIN");
      await c2.query("SELECT pg_advisory_xact_lock_shared($1::int, $2::int)", [PAVZA_ZAKLEP_RAZRED, eventId]);
      zapisano = (await c2.query(
        `UPDATE orders SET stripe_checkout_session_id=$2, checkout_url=$3, checkout_expires_at=to_timestamp($4)
          WHERE id=$1 AND status='pending' AND NOT (SELECT ev.sales_paused FROM events ev WHERE ev.id = orders.event_id) RETURNING id`,
        [oid, seja.id, seja.url, seja.expires_at])).rows.length;
      // Zavrnjeno: narocilo preklicemo (ce se caka; kupec ni placal nicesar, pristojbine ni) in sejo zabelezimo (pospravljalec jo najde, ce expire spodaj ne uspe).
      if (!zapisano) await c2.query(
        `UPDATE orders SET stripe_checkout_session_id = COALESCE(stripe_checkout_session_id, $2), checkout_expires_at = COALESCE(checkout_expires_at, to_timestamp($3)),
                status = CASE WHEN status = 'pending' THEN 'cancelled' ELSE status END, cancelled_at = CASE WHEN status = 'pending' THEN NOW() ELSE cancelled_at END
          WHERE id=$1`, [oid, seja.id, seja.expires_at]);
      await c2.query("COMMIT");
    } catch (e) { await c2.query("ROLLBACK").catch(() => {}); c2.release(e); c2 = null; throw e; }   // pokvarjene povezave ne vracamo v pool
    if (!zapisano) {
      c2.release(); c2 = null;
      const sS = placilaStripe.stripe();
      if (sS) Promise.resolve().then(() => sS.checkout.sessions.expire(seja.id))
        .then(() => console.log(`[pavza] narocilo ${nr.public_ref}: seja ${seja.id} ustvarjena po preklicu, zaprta`))
        .catch((e) => console.error(`[pavza] POZOR: seja ${seja.id} narocila ${nr.public_ref} ni zaprta (${e && e.message}); ce bo placana, vrne zakljuci()`));
      res.status(409).send(NAPAKA_PAVZA_PRODAJE);
      return null;
    }
  } catch (e) {
    if (c2) c2.release();
    console.error(`[stripe] Checkout seja za narocilo ${oid} ni uspela:`, e && (e.message || e));
    return neuspeh(pool, 502, "Payment provider is unavailable. Please try again.");
  }
  try { return await odgovorNarocila(c2, oid); } catch (e) { c2.release(e); c2 = null; throw e; } finally { if (c2) c2.release(); }
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
// checkout_url samo, dokler je Stripova seja veljavna (#149): potekla seja ima rok `checkout_expires_at`, narocilo pa ostane `pending`, dokler ga ne
// pospravi pospravljalec (do ~10 min po roku). V tem oknu odgovor namesto potekle povezave pove `checkout_url: null` + `checkout_expired: true`
// (DODANO polje; narocilo je potem kmalu `cancelled`, ali `paid`, ce je kupec placal tik pred rokom). Alias `o`.
const SQL_CHECKOUT_URL = `CASE WHEN o.status = 'pending' AND (o.checkout_expires_at IS NULL OR o.checkout_expires_at > NOW()) THEN o.checkout_url END AS checkout_url,
  (o.status = 'pending' AND o.checkout_url IS NOT NULL AND o.checkout_expires_at IS NOT NULL AND o.checkout_expires_at <= NOW()) AS checkout_expired,
  -- Odlozeno placilo (SEPA ipd.): seja je opravljena, denar se ni potrjen (placila_stripe.js oznaciVObdelavi: checkout_url NULL ob obstojeci seji). Ni »potekla«.
  (o.status = 'pending' AND o.stripe_checkout_session_id IS NOT NULL AND o.checkout_url IS NULL) AS payment_processing`;
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
    `SELECT ${STOLPCI_VSTOPNICE}, ${STOLPCI_VIP_VSTOPNICE}, ${STOLPCI_IMETNIKA}, ${SQL_SPOR_ODPRT} AS payment_disputed FROM tickets t JOIN orders o ON o.id = t.order_id ${JOIN_IMETNIK}
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
// M2 (pregled #316): zadnja preverba pavze tik pred COMMIT-om nakupa (vstopnice, gost, miza): pocaka na COMMIT hkratne pavze in prebere svezo vrednost;
// brez tega bi brezplacen/testni nakup (takoj `paid`), ki je dogodek prebral pred pavzo, uspel po njej. Vrne true, ce je ustavljena.
// Zaklep je ADVISORY na dogodek (pregled #316 M10), ne vrstica `events`: deljen pri nakupu, izkljucen pri pavzi (PATCH ga vzame PO zaklepu vrstice dogodka).
// Zaklep vrstice (FOR SHARE) bi se pri nakupu mize (drzi club_tables FOR SHARE) zaklenil s PUT /business/events/:id/vip (dogodek -> mize). Advisory razreda
// PAVZA_ZAKLEP_RAZRED ne vzame nihce drug, nakup ga vzame ZADNJEGA, pavza pa ne caka na nic, kar drzi nakup -> brez mrtve zanke. Branje po zaklepu je nov stavek
// (READ COMMITTED: svez posnetek), zato vidi commitano pavzo.
const PAVZA_ZAKLEP_RAZRED = 73112;   // dvodelni advisory kljuc (razred, id dogodka); 73110 = cakajoca narocila
// En krozni klic (dva stavka v enem sporocilu, preprost protokol): nakup vstopnic drzi vrstico dogodka (sprozilec zaloge) do COMMIT-a, zato vsak dodaten klic
// podaljsa zaporedje nakupov (test_obremenitev). Vsak stavek ima v READ COMMITTED svoj posnetek: drugi vidi pavzo, commitano med cakanjem na zaklep.
async function pavzaPredCommitom(c, eventId) {
  const id = Number(eventId);
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error("pavzaPredCommitom: neveljaven id dogodka");
  const izid = await c.query(`SELECT pg_advisory_xact_lock_shared(${PAVZA_ZAKLEP_RAZRED}, ${id}); SELECT sales_paused FROM events WHERE id = ${id}`);
  const r = Array.isArray(izid) ? izid[izid.length - 1] : izid;
  return !!(r.rows[0] && r.rows[0].sales_paused);
}
// Pavza prodaje (055, I53): `sales_paused` velja za VSE nakupne poti (vstopnice, gost, VIP miza), ker vse klicejo to funkcijo. Klicatelj MORA brati
// e.sales_paused (manjkajoc stolpec v SELECT-u = undefined = pavza se ne bi upostevala; test_prodaja_pavza.js to ujame za vse tri poti).
// Besedilo vsebuje »not on sale«: star iOS (APIErrorMessages) in splet (napake.js) ga po tem podnizu prevedeta v »This event is not on sale.«
// (brez tega bi 409 pokazal »This is already in use.«). Nov odjemalec naj bere `sales_paused` / `on_sale` na dogodku.
const NAPAKA_PAVZA_PRODAJE = "Ticket sales are paused. This event is not on sale right now.";
function napakaProdaje(e, { zahtevajCeno }) {
  if (e.status !== "published" || e.hidden) return [409, "Event is not on sale."];
  if (e.sales_paused === true) return [409, NAPAKA_PAVZA_PRODAJE];
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
// Neobvezna potrditev cene vstopnice (#277 N2, kot pri VIP mizi): `expected_price_cents` = cena ENE vstopnice v centih, ki jo je kupec videl.
// Manjka ali null = brez preverbe (star odjemalec). Vrne { cena: number|null } ali { napaka }. Ni del vsebine nakupa (odtis idempotence se ne spremeni).
function pricakovanaCenaIzTela(b) {
  const v = b ? b.expected_price_cents : undefined;
  if (v === undefined || v === null) return { cena: null };
  if (!Number.isInteger(v) || v < 0) return { napaka: "expected_price_cents must be a non-negative integer (cents)." };
  return { cena: v };
}
const SPREMENJENA_CENA_VSTOPNICE = "The ticket price has changed.";
// Razlicica pogojev ob nakupu Z RACUNOM (044, #215): neobvezno polje telesa `terms_version`. Ni del vsebine nakupa (odtis idempotence se ne spremeni).
// Vrne { verzija: string|null } ali { napaka }. Manjka ali null = NULL v bazi (star odjemalec); isti regex kot pri gostu in v CHECK-u migracije 044.
const TERMS_VERZIJA_RE = /^[A-Za-z0-9._:-]{1,40}$/;
function pogojiIzTela(b) {
  const v = b ? b.terms_version : undefined;
  if (v === undefined || v === null) return { verzija: null };
  if (typeof v !== "string" || !TERMS_VERZIJA_RE.test(v)) return { napaka: "terms_version is invalid." };
  return { verzija: v };
}
// Trenutna razlicica pogojev uporabe (#260 N2). OB NOVI RAZLICICI POGOJEV posodobi skupaj s spletom (TERMS_VERSION) in iOS (LegalLinks.termsVersion);
// glej docs/ARCHITECTURE.md »Razlicica pogojev«. Streznik nakupa zaradi druge razlicice NE zavrne (star iOS v rokah uporabnikov poslje starejso
// ali nobene) in shrani, kar je poslal odjemalec (kar je kupec dejansko videl); samo zapise opozorilo v dnevnik.
const TRENUTNI_POGOJI = "1.1.4";
const POGOJI_OPOZORILO_MS = Math.max(0, Number(process.env.POGOJI_OPOZORILO_MS) || 60_000);   // najvec eno opozorilo na (pot, razlicico) v tem oknu
const POGOJI_OPOZORILO_KLJUCEV = 200;   // meja pomnilnika: razlicic je lahko poljubno (vsak niz do 40 znakov)
const pogojiOpozorjeno = new Map();     // "pot|razlicica" -> cas zadnjega opozorila
// Brez osebnih podatkov: samo pot, poslana razlicica (ze preverjena z TERMS_VERZIJA_RE) in javna referenca narocila.
function opozoriPogoje(pot, verzija, ref) {
  if (verzija === TRENUTNI_POGOJI) return;
  const zdaj = Date.now(), k = pot + "|" + (verzija ?? "");
  const zadnjic = pogojiOpozorjeno.get(k);
  if (zadnjic !== undefined && zdaj - zadnjic < POGOJI_OPOZORILO_MS) return;
  if (zadnjic === undefined && pogojiOpozorjeno.size >= POGOJI_OPOZORILO_KLJUCEV) {
    for (const [kk, t] of pogojiOpozorjeno) if (zdaj - t >= POGOJI_OPOZORILO_MS) pogojiOpozorjeno.delete(kk);
    if (pogojiOpozorjeno.size >= POGOJI_OPOZORILO_KLJUCEV) return;   // poplava razlicnih razlicic: ne pisi vec, dokler okno ne potece
  }
  pogojiOpozorjeno.set(k, zdaj);
  console.warn(`[pogoji] ${pot}: terms_version ${verzija == null ? "manjka" : JSON.stringify(verzija)} (trenutna ${TRENUTNI_POGOJI}), narocilo ${ref}; nakup sprejet`);
}
function idemIstaVsebina(a, b) {
  return a.event_id === b.event_id && a.quantity === b.quantity
    && (a.table_id ?? null) === (b.table_id ?? null) && (a.package_id ?? null) === (b.package_id ?? null);
}
// Branje po kljucu (uporabnik IZ ZETONA, nikoli iz zahteve: kljuc drugega uporabnika je neviden, I3).
// Cakajoce narocilo s Stripovo sejo, ki je ze potekla (brez alias-a `o`, za poizvedbe po kljucu).
const SQL_ISTEK_SEJE = `(status = 'pending' AND checkout_url IS NOT NULL AND checkout_expires_at IS NOT NULL AND checkout_expires_at <= NOW()) AS checkout_expired`;
// Ponovitev kljuca, ko je Stripova seja narocila potekla (#149): checkout_url se NE vrne. Ce klicatelj ne drzi povezave z bazo (db === pool),
// narocilo takoj preverimo pri Stripu (placano tik pred rokom -> paid, potekla seja -> cancelled) in presodimo na svezem stanju; sicer
// (plast 3: klicatelj drzi povezavo, pool bi ob navali zastal) preverimo v ozadju in odgovorimo request_in_progress: ponovni poskus pride
// po plasti 1 in dobi dokoncen odgovor. Vrne osvezeno vrstico ali null (odgovor je ze poslan).
async function idemPotekloNarocilo(res, db, obst, preberi) {
  if (db === pool) {
    await stripePlacila.preveriPoteklo(obst.id);
    const sveze = await preberi(pool);
    if (sveze && !(sveze.status === "pending" && sveze.checkout_expired)) return sveze;
  } else {
    setImmediate(() => { stripePlacila.preveriPoteklo(obst.id).catch(() => {}); });
  }
  res.set("Retry-After", "2");
  res.status(409).json({ error: "request_in_progress", message: "Your previous attempt is still being processed. Please try again in a moment." });
  return null;
}
async function idemPoisci(db, userId, kljuc) {
  const r = await db.query(
    `SELECT id, event_id, quantity, table_id, package_id, status, checkout_url, ${SQL_ISTEK_SEJE} FROM orders WHERE user_id = $1 AND idempotency_key = $2`, [userId, kljuc]);
  return r.rows[0] || null;
}
async function idemPoId(db, oid) {
  const r = await db.query(
    `SELECT id, event_id, quantity, table_id, package_id, status, checkout_url, ${SQL_ISTEK_SEJE} FROM orders WHERE id = $1`, [oid]);
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
       ${SQL_CHECKOUT_URL}
     FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = o.club_id WHERE o.id = $1`, [oid]);
  const vst = await vstopniceNarocil([oid], db);
  const o = nr.rows[0];
  // mode: "test" (takoj placano, nic zaracunano) | "stripe" (placa na checkout_url; vstopnice nastanejo po placilu).
  // checkout_url je samo pri cakajocem Stripe narocilu (spremembe API-ja so samo dodajanje: star odjemalec ga spregleda).
  const telo = { mode: o.is_test ? "test" : "stripe", order: o, tickets: vst[oid] || [] };
  if (!o.is_test) telo.checkout_url = o.status === "pending" ? o.checkout_url : null;   // potekla seja: null + order.checkout_expired (SQL_CHECKOUT_URL)
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
  if (obst.status === "pending" && obst.checkout_expired) {
    obst = await idemPotekloNarocilo(res, db, obst, (d) => idemPoId(d, obst.id));
    if (!obst) return;
  }
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
  const pogoji = pogojiIzTela(req.body);
  if (pogoji.napaka) return res.status(400).send(pogoji.napaka);
  const pricakovana = pricakovanaCenaIzTela(req.body);
  if (pricakovana.napaka) return res.status(400).send(pricakovana.napaka);
  if (!(await nakupDovoljenje(req, res))) return;
  let c;
  try { c = await pool.connect(); } catch (err) { nakupIzstopi(); console.error(err); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
  const d = nakupDrzalec(c);
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
              e.capacity, e.sold_count, e.sales_open_at, e.sales_close_at, e.sales_paused, e.vat_rate, c.hidden,
              c.stripe_account_id, c.stripe_charges_enabled, c.stripe_account_livemode, c.commission_bps,
              c.legal_name, c.legal_address, c.registration_number, c.tax_number, c.vat_payer, c.contact_phone, c.contact_email, c.is_demo, c.is_official
       FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1`, [id]
    );
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    const e = er.rows[0];
    // Demo klub (050): 409 PRED zalogo, nacinom placila in Stripom; izjema vloga admin (testiranje toka, DECISIONS 13. 10. 2026).
    const demo = napakaDemoKluba(e, req.user.role);
    if (demo) { await c.query("ROLLBACK"); return res.status(409).json(demo); }
    const np = napakaProdaje(e, { zahtevajCeno: true });
    if (np) { await c.query("ROLLBACK"); return res.status(np[0]).send(np[1]); }
    // Potrditev cene (#277 N2): cena vstopnice se je med ogledom in nakupom spremenila -> 409, nic ni zaracunano ali rezervirano.
    if (pricakovana.cena !== null && pricakovana.cena !== e.ticket_price_cents) { await c.query("ROLLBACK"); return res.status(409).send(SPREMENJENA_CENA_VSTOPNICE); }
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
    const test = nacin === "test";
    const skupaj = e.ticket_price_cents * q;
    const npk = napakaKlubaBrezStripa(nacin, skupaj);   // I49: klub brez Stripa zavrne samo placljivo
    if (npk) { await c.query("ROLLBACK"); return res.status(409).send(npk); }
    const np2 = napakaProdajalca(e, nacin, skupaj);
    if (np2) { await c.query("ROLLBACK"); return res.status(409).json(np2); }
    // 0 EUR (#191): Stripe Checkout ima najmanjsi znesek (Stripe zavrne sejo, nakup bi koncal s 502), zato brezplacno narocilo NE gre v Stripe:
    // takoj `paid`, brez provizije (provizija od 0 je 0) in brez cakajocega narocila; zaloga, idempotenca in starost veljajo enako kot pri placanih.
    const placanoTakoj = test || skupaj === 0;
    if (skupaj === 0) {
      const brezplacno = await omejitevBrezplacnih(c, { userId: req.user.userId, eventId: e.id, enot: q });
      if (brezplacno) { await c.query("ROLLBACK"); return res.status(409).json(brezplacno); }
    }
    if (!placanoTakoj) {
      const omejitev = await omejitevCakajocih(c, req.user.userId, e.id);
      if (omejitev) { await c.query("ROLLBACK"); return res.status(409).send(omejitev); }
    }

    const platformno = placilaStripe.jePlatformniProdajalec(e);   // I50: prodajalec je platforma (uradni profil Outly): provizije ni, racuna kluba ni
    const provizija = platformno ? 0 : provizijaCentov(skupaj, e.commission_bps);
    const ref = javnaRef();
    const pi = test ? "test_" + crypto.randomUUID() : null;

    // Sprožilec orders_rezerviraj zaklene dogodek in preveri zalogo še enkrat (tudi za cakajoce narocilo: zaloga je rezervirana).
    // receipt_mail_attempts = 0: potrdilo kupcu je dolgovano ze od trenutka, ko je narocilo `paid` (042, #95).
    const or = await c.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency,
                           application_fee_cents, vat_rate, status, stripe_payment_intent_id, buyer_email, paid_at, idempotency_key,
                           stripe_account_id, receipt_mail_attempts, terms_version, terms_accepted_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CASE WHEN $11 = 'paid' THEN NOW() END,$14,$15,CASE WHEN $11 = 'paid' THEN 0 END,$16::text,CASE WHEN $16::text IS NOT NULL THEN NOW() END) RETURNING id`,
      [ref, req.user.userId, e.id, e.club_id, q, e.ticket_price_cents, skupaj, e.currency, provizija, e.vat_rate,
       placanoTakoj ? "paid" : "pending", pi, u.email, req.idemKljuc || null, placilaStripe.racunNarocila(placanoTakoj, platformno, e.stripe_account_id), pogoji.verzija]
    );
    const oid = or.rows[0].id;
    if (placanoTakoj) {
      await c.query(
        `INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [oid, e.id, q]
      );
    }
    if (await pavzaPredCommitom(c, e.id)) { await c.query("ROLLBACK"); return res.status(409).send(NAPAKA_PAVZA_PRODAJE); }   // M2, I53
    await c.query("COMMIT");
    opozoriPogoje("POST /events/:id/orders", pogoji.verzija, ref);

    // Stripe (#274): nakupStripeSeja povezavo in dovoljenje sprosti takoj, Stripe tece brez njiju in vrne telo odgovora (null = odgovor ze poslan).
    // POZOR: pri brezplacnem/testnem nakupu tu se drzimo odjemalca c. Branje po COMMIT-u gre prek c, NE prek
    // pool: pri 10+ hkratnih nakupih (pool ima privzeto 10 povezav) bi vsak
    // zahtevek držal svojo povezavo in čakal na enajsto -> celoten backend
    // obvisi, dokler ga Render ne zažene znova (ugotovljeno s testom sočasnosti). Stripe pot drzi najvec eno povezavo naenkrat (brez cakanja na drugo).
    const telo = placanoTakoj ? await odgovorNarocila(c, oid)
      : await nakupStripeSeja(res, d, { oid, opis: `${e.title} – ${q === 1 ? "1 ticket" : q + " tickets"}`,
        kolicina: q, cenaEnoteCents: e.ticket_price_cents, racunKluba: platformno ? null : e.stripe_account_id, platformno, email: u.email, eventId: e.id, odjemalec: odjemalecNakupa(req), locale: localeNakupa(req) });
    if (!telo) return;
    console.log(`Nakup (${placanoTakoj && !test ? "brezplacno" : nacin}): naročilo ${ref}, uporabnik ${req.user.userId}, dogodek ${e.id}, ${q}x ${e.ticket_price_cents} c`);
    if (placanoTakoj) posljiPotrdiloKupcu(oid);   // brez await: odgovor ne caka na Resend; napaka maila ne podre nakupa (pospravljalec ponovi)
    return res.status(201).json(telo);
  } catch (err) {
    if (d.drzi) await c.query("ROLLBACK").catch(() => {});   // po sprostitvi (nakupStripeSeja, #274) c ni vec nas
    if (napakaZasedenosti(err)) { console.error(err.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    // Unikatni indeks po kljucu je dokoncna resnica: zmagovalec je commitan, vrni njegovo narocilo (plast 3 to ze preprecuje).
    if (idemV && err && err.code === "23505" && err.constraint === "orders_idempotency_key" && await idemPoKonfliktu(req, res, c, idemV)) return;
    // Sprožilec: "Ni dovolj vstopnic" pride kot check_violation.
    if (err && err.code === "23514") return res.status(409).send(/Ni dovolj/.test(err.message) ? "Not enough tickets left." : "Order rejected: " + (err.constraint || err.message));
    console.error(err);
    return res.status(500).send("Server error.");
  } finally { try { d.sprosti(); } finally { if (req.idem) req.idem.sprosti(); } }
});

// GET /me/orders — moja naročila z vstopnicami.
app.get("/me/orders", requireAuth, async (req, res) => {
  try {
    await prevzemiGostujocaNarocila(req.user.userId, true);
    const preberi = () => pool.query(
      `SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, e.start_at, e.poster_url, cl.name AS club_name,
              ${SQL_CHECKOUT_URL}
       FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = o.club_id
       WHERE o.user_id = $1 AND NOT (o.status IN ('cancelled','failed') AND o.paid_at IS NULL)
         AND o.guest_list_id IS NULL   -- guest lista (035, I24) ni nakup: brez zneska/racuna; vstopnice so v GET /me/tickets, lista v GET /me/guest-lists
       ORDER BY o.created_at DESC LIMIT 100`, [req.user.userId]
    );
    let r = await preberi();
    // Potekla Stripova seja (#149): checkout_url ni vec veljaven; narocila preverimo pri Stripu (najvec 3 cakajoca na uporabnika, vzporedno) in seznam
    // preberemo znova: placano tik pred rokom je zdaj paid, potekla seja je cancelled (in izpade iz seznama). Kar Stripe ne potrdi, ostane
    // `pending` z checkout_url null + checkout_expired true.
    const potekla = r.rows.filter((o) => o.checkout_expired).map((o) => o.id);
    if (potekla.length) {
      await Promise.all(potekla.map((id) => stripePlacila.preveriPoteklo(id)));
      r = await preberi();
    }
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
// Spor (chargeback, #190, Martin 12. 10. 2026): vstopnice naroceno na vratih NE veljajo, dokler je PRAVI spor odprt (Stripova statusa needs_response, under_review), in za vedno ob `lost`;
// poizvedba (warning_needs_response, warning_under_review) NI chargeback in vrat ne zapre; spet veljajo ob won | warning_closed | prevented. En indeksiran EXISTS (spori_narocilo_idx) v ISTI poizvedbi, ki jo sken ze dela; brez klica Stripa. Alias naroceno: `o`.
const SQL_SPOR_ODPRT = "EXISTS (SELECT 1 FROM spori sp WHERE sp.order_id = o.id AND sp.stanje IN ('needs_response', 'under_review', 'lost'))";
const SQL_VSTOPNICE_POGLED = `SELECT ${STOLPCI_VSTOPNICE}, ${STOLPCI_VIP_VSTOPNICE}, o.public_ref, o.status AS order_status,
              e.title AS event_title, e.start_at, e.end_at, e.poster_url, e.min_age,
              cl.id AS club_id, cl.name AS club_name, ${PRIZORISCE_NASLOV}, cl.logo_url, ${PRIZORISCE_E},
              ${STOLPCI_IMETNIKA}, bu.username AS buyer_username,
              (t.status = 'valid' AND e.start_at > NOW() AND o.guest_list_id IS NULL AND NOT ${SQL_SPOR_ODPRT}) AS transferable,   -- vstopnice guest liste se ne prenasajo (035); ob odprtem/izgubljenem sporu tudi ne (#278)
              ${SQL_SPOR_ODPRT} AS payment_disputed   -- #190: spor (chargeback) odprt ali izgubljen: na vratih ne velja (NOVO polje; status vstopnice ostane valid)
       FROM tickets t JOIN orders o ON o.id = t.order_id
       JOIN events e ON e.id = t.event_id JOIN clubs cl ON cl.id = e.club_id ${PRIZORISCE_JOIN}
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
const GOST_POSTA_ZASTONJ_DNEVNO = okoljeCelo("GOST_POSTA_ZASTONJ_DNEVNO", 300, 1, 1000000);   // globalna dnevna meja mailov gostom za 0 EUR (brez placila in potrditve naslova)
const GOST_POSTA_ZASTONJ_NA_NASLOV = 3;                                                     // mailov za 0 EUR na normaliziran naslov na 24 h
const GOST_POSTA_SOCASNIH = 3;                                                              // socasnih posiljanj v procesu
const GOST_POSTA_TIMEOUT_MS = okoljeCelo("GOST_POSTA_TIMEOUT_MS", 10000, 100, 60000);        // rok za klic Resenda
const GOST_POSTA_PONOVI_MS = okoljeCelo("GOST_POSTA_PONOVI_MS", 120000, 0, 3600000);   // pospravljalec neposlanih mailov; 0 = izklop
const GOST_POSTA_PREMOR_MS = okoljeCelo("GOST_POSTA_PREMOR_MS", 120000, 0, 3600000);   // premor po 1. neuspelem poskusu; naslednji so mnogokratniki
const GOST_POSTA_REZERVA_MS = okoljeCelo("GOST_POSTA_REZERVA_MS", 30000, 0, 600000);   // rezerva za pripravo maila (QR, PDF) povrh roka Resenda
// Premor po n-tem neuspelem poskusu (indeks n; 0 = prvi poskus takoj): 2 min, 5 min, 15 min, 1 h, 3 h, 12 h, 24 h (pri privzetih 120000 ms), skupaj 8 poskusov.
// Spodnja meja premora = rok Resenda + rezerva (#201): prevzem v bazi ne sme potekniti, dokler isto narocilo (v tem ali drugem procesu) se poslje.
const GOST_POSTA_PREMOR_MIN_MS = GOST_POSTA_TIMEOUT_MS + GOST_POSTA_REZERVA_MS;
const GOST_POSTA_PREMORI = [0, 1, 2.5, 7.5, 30, 90, 360, 720].map((x) => x === 0 ? 0 : Math.max(Math.round(x * GOST_POSTA_PREMOR_MS), GOST_POSTA_PREMOR_MIN_MS));
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

// Stikalo nakupa brez racuna (I22). Privzeto ZAPRTO v vseh nacinih (503); velja SAMO za nakup (POST /guest/events/:id/orders), ogled, preklic in
// prevzem obstojecih gostujocih narocil (GET /guest/order, POST /guest/order/cancel, GET /guest/ticket, prevzem ob GET /me) delajo naprej.
// - zivi kljuc (sk_live_): GOST_NAKUP_LIVE=1 - pogoji in politika zasebnosti morata biti objavljeni, preden gostje placujejo pravi denar;
// - sandbox (sk_test_), testni nacin (TEST_PLACILA) ali brez kljuca: GOST_NAKUP_TEST=1 (za ekipo). Brez tega bi kdorkoli prek javne poti dobil
//   brezplacne VELJAVNE vstopnice brez potrditve maila (sandbox kartica 4242 ali testni nacin brez placila; 10 nakupov/h/IP -> razprodan dogodek, #249).
// Spremenljivki se ne prekrivata: GOST_NAKUP_LIVE ne odpre sandboxa in GOST_NAKUP_TEST ne zivega nacina.
function gostStikalo(req, res, next) {
  res.set("Cache-Control", "no-store");
  // TEST_PLACILA=true ob sk_live_ nima ucinka (#191): velja zivo stikalo, gostje ne kupujejo brez placila.
  const vklopljen = placilaStripe.jeLive() ? process.env.GOST_NAKUP_LIVE === "1" : process.env.GOST_NAKUP_TEST === "1";
  if (!vklopljen) return res.status(503).send("Guest checkout is not available yet.");
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
  const pricakovana = pricakovanaCenaIzTela(b);
  if (pricakovana.napaka) return res.status(400).send(pricakovana.napaka);
  req.gost = { eventId, email, quantity: q, dob, terms: b.terms_version, pricakovanaCena: pricakovana.cena };
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
  const r = await db.query(`SELECT id, event_id, quantity, status, checkout_url, user_id, ${SQL_ISTEK_SEJE} FROM orders WHERE guest_email = $1 AND idempotency_key = $2`, [email, kljuc]);
  return r.rows[0] || null;
}
// Isto kot idemOdgovori: isti nakup + aktivno narocilo -> 201 s trenutnim stanjem (in SVEZIM zetonom: cistopisa prvega ni); drug nakup -> 422;
// neaktivno -> 409. Odgovor je poslan vedno.
async function gostIdemOdgovori(req, res, db, obst) {
  const g = req.gost;
  if (obst.event_id !== g.eventId || obst.quantity !== g.quantity) return idemNapacnaVsebina(res);
  if (obst.status === "pending" && obst.checkout_expired) {
    obst = await idemPotekloNarocilo(res, db, obst, async (d) => {
      const r = await d.query(`SELECT id, event_id, quantity, status, checkout_url, user_id, ${SQL_ISTEK_SEJE} FROM orders WHERE id = $1`, [obst.id]);
      return r.rows[0] || null;
    });
    if (!obst) return;
  }
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
  const d = nakupDrzalec(c);
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
              e.capacity, e.sold_count, e.sales_open_at, e.sales_close_at, e.sales_paused, e.vat_rate, c.hidden,
              c.stripe_account_id, c.stripe_charges_enabled, c.stripe_account_livemode, c.commission_bps,
              c.legal_name, c.legal_address, c.registration_number, c.tax_number, c.vat_payer, c.contact_phone, c.contact_email, c.is_demo, c.is_official
       FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1`, [g.eventId]
    );
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    const e = er.rows[0];
    // Demo klub (050): gost nima vloge, zato vedno 409 (PRED zalogo in Stripom).
    const demo = napakaDemoKluba(e, undefined);
    if (demo) { await c.query("ROLLBACK"); return res.status(409).json(demo); }
    const np = napakaProdaje(e, { zahtevajCeno: true });
    if (np) { await c.query("ROLLBACK"); return res.status(np[0]).send(np[1]); }
    if (g.pricakovanaCena !== null && g.pricakovanaCena !== e.ticket_price_cents) { await c.query("ROLLBACK"); return res.status(409).send(SPREMENJENA_CENA_VSTOPNICE); }   // #277 N2
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
    const test = nacin === "test";
    const skupaj = e.ticket_price_cents * g.quantity;
    const npk = napakaKlubaBrezStripa(nacin, skupaj);   // I49: klub brez Stripa zavrne samo placljivo
    if (npk) { await c.query("ROLLBACK"); return res.status(409).send(npk); }
    const np2 = napakaProdajalca(e, nacin, skupaj);
    if (np2) { await c.query("ROLLBACK"); return res.status(409).json(np2); }
    const placanoTakoj = test || skupaj === 0;   // 0 EUR gre mimo Stripa (#191), kot pri nakupu z racunom
    if (skupaj === 0) {
      const brezplacno = await omejitevBrezplacnih(c, { gostEmail: g.email, eventId: e.id, enot: g.quantity });
      if (brezplacno) { await c.query("ROLLBACK"); return res.status(409).json(brezplacno); }
    }
    if (!placanoTakoj && e.capacity !== null) {
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

    const platformno = placilaStripe.jePlatformniProdajalec(e);   // I50: prodajalec je platforma (uradni profil Outly): provizije ni, racuna kluba ni
    const provizija = platformno ? 0 : provizijaCentov(skupaj, e.commission_bps);
    const ref = javnaRef();
    const pi = test ? "test_" + crypto.randomUUID() : null;
    const or = await c.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency,
                           application_fee_cents, vat_rate, status, stripe_payment_intent_id, buyer_email, paid_at, idempotency_key,
                           stripe_account_id, guest_email, guest_terms_version, guest_terms_accepted_at, guest_age_min)
       VALUES ($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CASE WHEN $10 = 'paid' THEN NOW() END,$13,$14,$12,$15,NOW(),$16) RETURNING id`,
      [ref, e.id, e.club_id, g.quantity, e.ticket_price_cents, skupaj, e.currency, provizija, e.vat_rate,
       placanoTakoj ? "paid" : "pending", pi, g.email, req.idemKljuc || null, placilaStripe.racunNarocila(placanoTakoj, platformno, e.stripe_account_id), g.terms, g.dob ? e.min_age : null]
    );
    const oid = or.rows[0].id;
    if (placanoTakoj) {
      await c.query(`INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [oid, e.id, g.quantity]);
    }
    const zeton = await gostKujZeton(c, oid);   // v isti transakciji: zeton velja takoj, ko je narocilo vidno
    if (await pavzaPredCommitom(c, e.id)) { await c.query("ROLLBACK"); return res.status(409).send(NAPAKA_PAVZA_PRODAJE); }   // M2, I53
    await c.query("COMMIT");
    opozoriPogoje("POST /guest/events/:id/orders", g.terms, ref);

    let telo;
    if (placanoTakoj) telo = await odgovorNarocila(c, oid);   // prek c (ne pool): glej opombo pri POST /events/:id/orders
    else {
      const povratna = { success_url: gostPovezava(zeton), cancel_url: gostPovezava(zeton) };   // stran naroclia: »Complete payment« / »Cancel order«
      telo = await nakupStripeSeja(res, d, { oid, opis: `${e.title} – ${g.quantity === 1 ? "1 ticket" : g.quantity + " tickets"}`,
        kolicina: g.quantity, cenaEnoteCents: e.ticket_price_cents, racunKluba: platformno ? null : e.stripe_account_id, platformno, email: g.email, eventId: e.id,
        odjemalec: "splet", povratna, locale: localeNakupa(req) });   // #274: povezavo in dovoljenje sprosti sama
      if (!telo) return;
    }
    telo.guest_token = zeton;
    console.log(`Nakup gosta (${placanoTakoj && !test ? "brezplacno" : nacin}): naročilo ${ref}, dogodek ${e.id}, ${g.quantity}x ${e.ticket_price_cents} c`);
    if (placanoTakoj) posljiGostuVstopnice(oid);   // brez await: odgovor ne caka na Resend; napaka maila ne podre nakupa (pospravljalec ponovi)
    return res.status(201).json(telo);
  } catch (err) {
    if (d.drzi) await c.query("ROLLBACK").catch(() => {});   // po sprostitvi (nakupStripeSeja, #274) c ni vec nas
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
  } finally { try { d.sprosti(); } finally { if (req.idem) req.idem.sprosti(); } }
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
            ${SQL_CHECKOUT_URL},
            e.id AS event_id, e.title AS event_title, e.start_at, e.end_at, e.poster_url, e.min_age,
            cl.id AS club_id, cl.name AS club_name, ${PRIZORISCE_NASLOV}, cl.logo_url, ${PRIZORISCE_E},
            ${sqlProdajalecSurov("cl")} AS seller_raw, ${placilaStripe.SQL_NAROCILO_PLATFORMNO("o")} AS platformno
       FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = o.club_id ${PRIZORISCE_JOIN} WHERE o.id = $1`, [oid]);
  if (!nr.rows.length) return null;
  const x = nr.rows[0];
  return {
    id: x.id, public_ref: x.public_ref, status: x.status, quantity: x.quantity, unit_price_cents: x.unit_price_cents,
    total_cents: x.total_cents, currency: x.currency, refunded_cents: x.refunded_cents, is_test: x.is_test,
    created_at: x.created_at, paid_at: x.paid_at, checkout_url: x.checkout_url, checkout_expired: x.checkout_expired, payment_processing: x.payment_processing,
    event_id: x.event_id, club_id: x.club_id, event_title: x.event_title, start_at: x.start_at, poster_url: x.poster_url, club_name: x.club_name,
    event: { id: x.event_id, title: x.event_title, start_at: x.start_at, end_at: x.end_at, poster_url: x.poster_url, min_age: x.min_age,
             club_id: x.club_id, club_name: x.club_name, address: x.address, city: x.city, logo_url: x.logo_url, ...prizoriscePolja(x) },
    seller: prodajalec({ ...x.seller_raw, is_official: false, is_platform: x.platformno === true }),   // prodajalec = organizator/klub dogodka, ne prizorisce (043, #94); I50: platforma po oznaki NAROCILA
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
    let order = await gostNarociloOdgovor(pool, oid);
    if (!order) return res.status(404).send("Order not found.");
    if (order.checkout_expired) {
      // Potekla Stripova seja (#149): preveri pri Stripu (najvec en klic na narocilo na PREVERI_OKNO_MS) in preberi svezo stanje.
      await stripePlacila.preveriPoteklo(oid);
      order = (await gostNarociloOdgovor(pool, oid)) || order;
    }
    let vstopnice = [];
    if (["paid", "partially_refunded"].includes(order.status)) {
      const r = await pool.query(`${SQL_VSTOPNICE_POGLED} WHERE t.order_id = $1 ORDER BY t.id`, [oid]);
      vstopnice = r.rows.map((t) => ({ ...t, qr: qrVstopnice(t), transferable: false }));   // prenos zahteva racun
    }
    return res.json({ order, tickets: vstopnice, seller: order.seller });   // seller tudi na vrhu (043, #94); isti objekt kot order.seller
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
    // I36 (#227): sandbox seja (cs_test_) ob zivem kljucu: Stripe je z zivim kljucem ne pozna (retrieve = 404 -> 502, gost ne bi mogel preklicati). Kot pospravljalec
    // (placila_stripe.js preveriEno): brez klica Stripa, naslednji korak narocilo preklice in sprosti zalogo (sandbox seje v zivem ni mogoce placati ali zakljuciti).
    const sandboxSeja = !!k.stripe_checkout_session_id && placilaStripe.jeLive() && /^cs_test_/.test(k.stripe_checkout_session_id);
    if (k.stripe_checkout_session_id && !sandboxSeja) {
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
    } else if (!k.stripe_checkout_session_id && Date.now() - new Date(k.created_at).getTime() < 60 * 1000) {
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
// Mail za 0 EUR (ne-testni) nima potrditve naslova in placila, zato: najvec GOST_POSTA_ZASTONJ_NA_NASLOV (3) mailov na NORMALIZIRAN naslov na 24 h in globalno
// GOST_POSTA_ZASTONJ_DNEVNO (300) na 24 h; nad mejo se mail IZPUSTI (ne ponavlja), nakup in guest_token v odgovoru ostaneta (pregled PR #203, 2. krog).
// Placano (total > 0, ne-testno) potrdilo ostane zakonska obveznost (ZVPot-1): nikoli izpuscen.
// Napaka maila NE sme podreti placila ali webhooka (klicatelji ne cakajo in ne vidijo izjem). Vrne true, ce je mail poslan.
const SQL_PRODAJALEC_MAIL = "cl.legal_name, cl.legal_address, cl.registration_number, cl.tax_number, cl.vat_payer";   // za sellerVrstice (043)
// ZVPot-1 7(1) drugi stavek (pravnik 2026-10-20, tabela vrstica 5): VSAKO pisno sporocilo potrosniku nosi celotno ime firme in sedez posiljatelja.
// Ena resnica za firmo platforme: POSREDNIK_VRSTICA, potrdilo (PLATFORMA_FIRMA) in noga vsakega maila (nogaMaila v gostResendPosli in ostalih posiljanjih).
const FIRMA_PLATFORME = "NEXT DIMENSIONS, družba za marketing, d.o.o.", SEDEZ_PLATFORME = "Trebče 81, 3256 Bistrica ob Sotli";
const POSREDNIK_VRSTICA = `${FIRMA_PLATFORME}, ${SEDEZ_PLATFORME}, luka@outly.si`;
const NOGA_MAILA = `Pošiljatelj / Sender: ${FIRMA_PLATFORME}, ${SEDEZ_PLATFORME}`;
// Noga z imenom firme in sedezem na koncu VSAKEGA maila (besedilo in HTML; 12 px, #555). Brez HTML-ja (samo besedilo) vrne samo besedilo.
function nogaMaila({ html, text }) {
  const n = NOGA_MAILA.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  return {
    html: html === undefined ? undefined : `${html}<p style="margin:24px 0 0;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.5;color:#555">${n}</p>`,
    text: text === undefined ? undefined : `${String(text).replace(/\s+$/, "")}\n\n${NOGA_MAILA}\n`,
  };
}
const POSTA_ODGOVOR = "luka@outly.si";
// Maili, ki so del nakupa (potrdilo kupcu, vstopnice gostu, prejeta vstopnica), so DVOJEZICNI: slovenski blok, locilo, angleski blok (#100, ZVPot-1 7/1: informacije pred
// sklenitvijo pogodbe v slovenscini). Podatki so eni, razdelke za vsak jezik gradi ista funkcija z `jez` ("sl" | "en") in jih izrise izrisiDvojezicno.
// Angleski blok je BESEDA ZA BESEDO enak kot pred #100 (testi ga preverjajo). Slovenski blok: vikanje, znesek z decimalno vejico, datum po sl-SI.
const JEZIKI_MAILA = ["sl", "en"];
const LOCILO_MAILA = "----------------------------------------";
const znesek = (centi, valuta, jez = "en") => {
  const niz = `${(centi / 100).toFixed(2)} ${String(valuta).trim()}`;
  return jez === "sl" ? niz.replace(".", ",") : niz;
};
const LJ_OBLIKE = Object.fromEntries([["sl", "sl-SI", " (ljubljanski čas)"], ["en", "en-GB", " (Ljubljana time)"]].map(([j, loc, pripis]) =>
  [j, { f: new Intl.DateTimeFormat(loc, { dateStyle: "full", timeStyle: "short", timeZone: "Europe/Ljubljana" }), pripis }]));
const ljDatum = (d, jez = "en") => LJ_OBLIKE[jez].f.format(new Date(d)) + LJ_OBLIKE[jez].pripis;
// Stavek o DDV glede na stopnjo, zamrznjeno na narocilu (events.vat_rate; NULL = klub ni dolocil): ne trdimo, da je DDV vkljucen, ce ne vemo.
// #101: ko stopnje ni, odloca DDV status prodajalca (clubs.vat_payer, 043): true -> cena vkljucuje DDV, false -> prodajalec ni zavezanec, null -> splosni stavek.
function davekStavek(vat, vatPayer, jez = "en") {
  const sl = jez === "sl";
  if (vat === null || vat === undefined) {
    if (vatPayer === true) return sl ? "Cena vključuje DDV." : "The price includes VAT.";
    if (vatPayer === false) return sl ? "Prodajalec ni zavezanec za DDV, zato DDV ni obračunan." : "The seller is not a VAT payer; no VAT is charged.";
    return sl ? "DDV se obračuna v skladu s statusom prodajalca." : "VAT is charged according to the seller's VAT status.";
  }
  const p = Math.round(Number(vat) * 1000) / 10;
  if (sl) return p > 0 ? `Cena vključuje DDV (${String(p).replace(".", ",")} %).` : "Prodajalec pri tej ceni ne obračuna DDV.";
  return p > 0 ? `The price includes VAT (${p}%).` : "The seller does not charge VAT on this price.";
}
// Razdelek »Seller« potrdila (gost in kupec z racunom): firma (nadomestek: ime kluba), sedez (nadomestek: naslov kluba), telefon, e-naslov,
// maticna in davcna stevilka ter DDV status (#94, #101). `o` nosi stolpce kluba iz SQL_PRODAJALEC_MAIL. Prodajalec je klub dogodka (pri gostovanem dogodku organizator).
function sellerVrstice(o, jez = "en") {
  const sl = jez === "sl";
  const s = prodajalec({ name: o.club_name, legal_name: o.legal_name, legal_address: o.legal_address, address: o.club_address, city: o.club_city,
    registration_number: o.registration_number, tax_number: o.tax_number, vat_payer: o.vat_payer, contact_phone: o.club_phone, contact_email: o.club_email });
  // I50: prodajalec je platforma (narocilo z oznako »platform«): vstopnico prodaja NEXT DIMENSIONS sama (podatki prodajalca iz vrstice kluba), brez stavka o posredniku.
  const platforma = o.stripe_account_id === placilaStripe.PLATFORMNI_RACUN;
  const podatki = [s.name, s.address, s.phone, s.email].filter(Boolean).join(", ");
  const vrstice = platforma
    ? [/next dimensions/i.test(s.name)
        ? `${sl ? "Vstopnico prodaja" : "The ticket is sold by"}: ${podatki}.`
        : `${sl ? "Vstopnico prodaja družba NEXT DIMENSIONS" : "The ticket is sold by NEXT DIMENSIONS"}: ${podatki}.`]
    : [`${sl ? "Vstopnico prodaja klub" : "The ticket is sold by the club"}: ${podatki}.`];
  const ident = [s.registration_number ? `${sl ? "Matična številka" : "Company registration number"}: ${s.registration_number}` : "", s.tax_number ? `${sl ? "Davčna številka" : "Tax number"}: ${s.tax_number}` : ""].filter(Boolean);
  if (ident.length) vrstice.push(`${ident.join(". ")}.`);
  if (s.vat_payer === true) vrstice.push(sl ? "Status DDV: prodajalec je zavezanec za DDV." : "VAT status: the seller is a VAT payer.");
  else if (s.vat_payer === false) vrstice.push(sl ? "Status DDV: prodajalec ni zavezanec za DDV." : "VAT status: the seller is not a VAT payer.");
  if (!platforma) vrstice.push(sl ? `Outly je samo posrednik: ${POSREDNIK_VRSTICA}.` : `Outly is only the intermediary: ${POSREDNIK_VRSTICA}.`);
  return vrstice;
}
// Slovnicno stevilo za »sedez« (1 sedez, 2 sedeza, 3-4 sedezi, 5+ sedezev; 101 = sedez, 102 = sedeza ...).
const sedezSl = (n) => (n % 100 === 1 ? "sedež" : n % 100 === 2 ? "sedeža" : n % 100 === 3 || n % 100 === 4 ? "sedeži" : "sedežev");
// Izris dvojezicnega maila. zgradi(jez) -> { naslovBesedila, naslovHtml, razdelki: [{ naslov, vrstice[], krepko?, slika?: [{cid, oznaka, alt}] }] }.
// Besedilo: blok sl, locilo, blok en. HTML: vsak blok v svojem <div lang>, vse prek GOST_POSTA_NIZ (podatki iz baze so escapani); povezava se zavije v <a>.
// Koda QR (slika) je v obeh blokih (ista priloga CID, dve sklicevanji), da jo bralec vsakega jezika vidi tam, kjer jo besedilo omenja.
function izrisiDvojezicno(zgradi, povezava) {
  const bloki = JEZIKI_MAILA.map((j) => zgradi(j));
  const besedilo = bloki.map((b) => `${b.naslovBesedila}\n\n` + b.razdelki.map((r) => `${r.naslov.toUpperCase()}\n${r.vrstice.join("\n")}`).join("\n\n")).join(`\n\n${LOCILO_MAILA}\n\n`) + "\n";
  const html = `<div style="font-family: Arial, sans-serif; line-height:1.5">` + bloki.map((b, i) =>
    (i ? `<hr style="margin:24px 0;border:0;border-top:1px solid #ccc">` : "") + `<div lang="${JEZIKI_MAILA[i]}"><h2>${GOST_POSTA_NIZ(b.naslovHtml)}</h2>` + b.razdelki.map((r) =>
      `<h3>${GOST_POSTA_NIZ(r.naslov)}</h3>` + r.vrstice.map((v) => {
        const e = GOST_POSTA_NIZ(v);
        const z = povezava && v.includes(povezava) ? e.replace(GOST_POSTA_NIZ(povezava), () => `<a href="${GOST_POSTA_NIZ(povezava)}">${GOST_POSTA_NIZ(povezava)}</a>`) : e;
        return `<p>${r.krepko ? `<strong>${z}</strong>` : z}</p>`;
      }).join("") + (r.slika || []).map((k) => qrSlikaHtml(k.cid, k.oznaka, k.alt)).join("")).join("") + `</div>`).join("") + `</div>`;
  return { besedilo, html };
}
// Vsebina potrdila kot razdelki { naslov, vrstice[] } za EN jezik `jez`; iz njih nastaneta besedilo in HTML (isto besedilo, brez oglasov).
function gostPotrdilo(o, povezava, prevzeto, kode = []) {
  return izrisiDvojezicno((jez) => {
    const T = (sl, en) => (jez === "sl" ? sl : en);
    // T9 (pravnik 2026-10-20): pri prodajalcu platformi (I50) ni kluba, je organizator (NEXT DIMENSIONS)
    const klub = o.stripe_account_id === placilaStripe.PLATFORMNI_RACUN ? T("organizator", "organiser") : T("klub", "club");
    const starost = o.min_age > 0
      ? T(`Starostna meja: ${o.min_age}+. Vsak obiskovalec mora izpolnjevati starostno mejo. Pri vhodu se preverja osebni dokument; ${klub} vam lahko zavrne vstop, če je ne izpolnjujete.`,
          `Age limit: ${o.min_age}+. Every visitor must meet the age limit. ID is checked at the door; the ${klub} may refuse entry if you don't meet it.`)
      : T("Brez starostne omejitve.", "No age limit.");
    const kodeVrstice = kode.length > 1
      ? [T("Prva koda QR je spodaj, vse vaše kode QR (ena na stran) so v priloženem PDF (outly-tickets.pdf). Pri vhodu pokažite eno kodo na osebo.",
           "The first QR code is below; all your QR codes (one per page) are in the attached PDF (outly-tickets.pdf). Show one code per person at the door.")]
      : kode.length ? [T("Koda QR je spodaj in v priloženem PDF (outly-tickets.pdf). Pokažite jo pri vhodu.", "The QR code is below and in the attached PDF (outly-tickets.pdf). Show it at the door.")] : [];
    const razdelki = [
      { naslov: T("Naročilo", "Order"), vrstice: [T(`Naročilo ${o.public_ref}. Čas naročila: ${ljDatum(o.paid_at || o.created_at, jez)}.`, `Order ${o.public_ref}, placed on ${ljDatum(o.paid_at || o.created_at, jez)}.`)] },
      { naslov: T("Dogodek", "Event"), vrstice: [o.event_title, ljDatum(o.start_at, jez), prizoriscePodatki(o), starost] },
      { naslov: T("Vstopnice", "Tickets"), vrstice: [`${o.quantity} x ${znesek(o.unit_price_cents, o.currency, jez)} = ${znesek(o.total_cents, o.currency, jez)}. ${davekStavek(o.vat_rate, o.vat_payer, jez)}`] },
      { naslov: T("Prodajalec", "Seller"), vrstice: sellerVrstice(o, jez) },
      { naslov: T("Brez pravice do odstopa", "No right of withdrawal"), vrstice: [T(
        "Pri vstopnicah za dogodek na določen datum pravice do odstopa od pogodbe ni (Zakon o varstvu potrošnikov ZVPot-1, 135. člen, 12. točka). Če je dogodek odpovedan ali prestavljen, veljajo pravila iz pogojev.",
        "There is no right of withdrawal for tickets to an event on a fixed date (Consumer Protection Act ZVPot-1, Article 135, point 12). If the event is cancelled or postponed, the rules in the terms apply.")] },
      { naslov: T("Pogoji", "Terms"), vrstice: [T(`Sprejeli ste pogoje uporabe Outly, različica ${o.guest_terms_version}: https://outly.si/terms`, `You accepted the Outly terms, version ${o.guest_terms_version}: https://outly.si/terms`)] },
      { naslov: T("Vaše vstopnice", "Your tickets"), vrstice: (prevzeto
        ? [T(`Vstopnice odprite v svojem računu Outly: ${povezava}`, `Open your tickets in your Outly account: ${povezava}`)]
        : [T(`Odprite vstopnice (kodo QR pokažite pri vhodu): ${povezava}`, `Open your tickets (show the QR code at the door): ${povezava}`),
           T("Ta povezava je vaša vstopnica. Ne delite je z nikomer, razen z osebami, ki pridejo z vami.", "This link is your ticket. Don't share it except with people coming with you."),
           T("Če z istim e-naslovom ustvarite račun Outly, se bodo vstopnice pojavile tam.", "If you create an Outly account with this email, your tickets will appear there.")])
        .concat(kodeVrstice),
        slika: kode.slice(0, 1).map((k) => ({ cid: k.cid, oznaka: oznakaKode(k, jez), alt: T("Koda QR vstopnice", "Ticket QR code") })) },
      { naslov: T("Pritožbe", "Complaints"), vrstice: [T(`Glede dogodka: obrnite se na ${klub === "klub" ? "klub" : "organizatorja"} (podatki zgoraj). Glede nakupa ali plačila: obrnite se na Outly na ${POSTA_ODGOVOR}.`,
        `About the event: contact the ${klub} (details above). About the purchase or the payment: contact Outly at ${POSTA_ODGOVOR}.`)] },
      { naslov: T("Vprašanja", "Questions"), vrstice: [T(`Odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR}.`, `Reply to this email or write to ${POSTA_ODGOVOR}.`)] },
    ];
    return { naslovBesedila: T(`Vaše vstopnice Outly - naročilo ${o.public_ref}`, `Your Outly tickets - order ${o.public_ref}`), naslovHtml: T("Vaše vstopnice Outly", "Your Outly tickets"), razdelki };
  }, povezava);
}
// Oznaka kode QR v mailu (»Ticket 2 of 3«) po jeziku; k.n / k.skupaj postavi klicalec. PDF ima angleski k.oznaka.
const oznakaKode = (k, jez) => (k.skupaj > 1 ? (jez === "sl" ? `Vstopnica ${k.n} od ${k.skupaj}` : `Ticket ${k.n} of ${k.skupaj}`) : "");
// --- priloge: QR kot vgrajena slika (CID) + PDF (migracija 034, vstopnica_priloge.js) ---
const QR_STAVEK = "This email and the attached PDF are your ticket. The QR code is valid for one entry: whoever shows it first gets in. Don't forward this email, post the code or share the link.";
const QR_STAVEK_SL = "To sporočilo in priloženi PDF sta vaša vstopnica. Koda QR velja za en vstop: vstopi tisti, ki jo pokaže prvi. Sporočila ne posredujte naprej, kode ne objavljajte in povezave ne delite z drugimi.";
const qrSlikaHtml = (cid, oznaka, alt = "Ticket QR code") => `<div style="margin:12px 0">${oznaka ? `<p style="margin:0 0 4px">${GOST_POSTA_NIZ(oznaka)}</p>` : ""}<img src="cid:${cid}" width="228" height="228" alt="${GOST_POSTA_NIZ(alt)}" style="display:block;width:228px;height:228px;border:1px solid #ccc"></div>`;
// Resend 3.5 posreduje telo strezniku neprepisano (JSON, kljuci snake_case: content_type, content_id): vsebina priloge je BASE64 niz (Buffer bi se serializiral
// napacno), `content_id` vgradi sliko (cid:). SDK tega NE tipizira in ne preverja (verzija 3.5.0): PREVERI ob vsaki nadgradnji SDK (npr. 4.x je prepisal polja v camelCase).
// Inline slika SAMO za prvo kodo (zanesljivost: sestavljanje je CPU na glavni niti; ostale kode so v PDF, ena na stran); sestavljanje je asinhrono in prepusca zanko (vstopnica_priloge.js).
async function prilogeVstopnic(ev, kode, imePdf, varnost = QR_STAVEK) {
  const starost = ev.min_age > 0 ? `Age limit: ${ev.min_age}+. Show a valid photo ID at the door.` : "";
  const priloge = [];
  if (kode.length) priloge.push({ filename: `${kode[0].cid}.png`, content: (await qrPng(kode[0].koda)).toString("base64"), content_type: "image/png", content_id: kode[0].cid });
  if (kode.length) {
    const pdf = await pdfVstopnice({
      dogodek: { naslov: ev.event_title, zacetek: ljDatum(ev.start_at), prizoriscePodatki: prizoriscePodatki(ev),
                 starost: ev.starostPdf || starost, organizator: [ev.club_phone, ev.club_email].filter(Boolean).join(" | ") },
      vstopnice: kode.map(k => ({ koda: k.koda, vrsta: k.vrsta, oznaka: k.oznaka })), varnost });
    priloge.push({ filename: imePdf, content: pdf.toString("base64"), content_type: "application/pdf" });
  }
  return priloge;
}
// Klic Resenda z rokom (Promise.race: SDK nima AbortSignal); po izteku poskus velja za neuspel, klic lahko vseeno uspe (mozen dvojnik).
// Vrne { data } ali { error } (Resend ob napaki ne vrze). Brez sledenja: Resend ga nastavlja na domeni, ne na mailu (glej STATE).
async function gostResendPosli({ to, subject, html, text, attachments }) {
  let timer;
  subject = zadevaMaila(subject);
  ({ html, text } = nogaMaila({ html, text }));   // ZVPot-1 7(1): firma in sedez posiljatelja v vsakem mailu
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

// Narocila / vstopnice, ki se v TEM procesu ravnokar posiljajo (#201): pospravljalec in nakup sta lahko hkrati pri istem; drugi klic ne sme prevzeti znova.
// (Med procesi varuje spodnja meja premora GOST_POSTA_PREMOR_MIN_MS.) Kljuc se doda pred cakanjem na mesto in odstrani v finally.
const gostVTeku = new Set();
const prenosVTeku = new Set();
async function posljiGostuVstopnice(oid) {
  if (!resend) return false;
  const kljuc = String(oid);   // kljuc mnozice vedno niz: id pride kot stevilo ali kot niz
  if (gostVTeku.has(kljuc)) return false;
  gostVTeku.add(kljuc);
  try {
    if (!(await gostPostaVstopi())) return false;
    try { return await gostPosljiEnoPosto(oid); }
    catch (err) { console.error(`Resend napaka (gost, vstopnice, narocilo ${oid}):`, err && (err.message || String(err))); return false; }
    finally { gostPostaIzstopi(); }
  } finally { gostVTeku.delete(kljuc); }
}
async function gostPosljiEnoPosto(oid) {
  const pre = (await pool.query(
    // Mail za 0 EUR (#191) je poleg povezave iz odgovora nakupa (guest_token) gostov dostop do vstopnic, vendar nima potrditve naslova ne placila:
    // ima svoji meji (spodaj). Meje testnega nacina veljajo samo za testna narocila.
    `SELECT guest_email, status, guest_mail_sent_at, guest_mail_attempts, public_ref, total_cents, COALESCE(stripe_payment_intent_id LIKE 'test_%', FALSE) AS is_test
       FROM orders WHERE id = $1`, [oid])).rows[0];
  if (!pre || !pre.guest_email || pre.status !== "paid" || pre.guest_mail_sent_at || pre.guest_mail_attempts >= GOST_POSTA_POSKUSOV) return false;
  // Meje (zloraba: mail na tuj naslov brez placila) veljajo za testna narocila in za narocila za 0 EUR: testna globalno na dan in 1 mail na naslov na 24 h,
  // brezplacna po GOST_POSTA_ZASTONJ_*. Potrdilo PLACANEGA narocila je zakonska obveznost (ZVPot-1): nikoli se ne odlozi ne izpusti, ob preseznem stevilu samo opozorilo (brez e-naslova).
  const brezplacno = !pre.is_test && Number(pre.total_cents) === 0;
  const dnevno = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_mail_sent_at > NOW() - INTERVAL '24 hours'")).rows[0].n;
  if (pre.is_test) {
    if (dnevno >= GOST_POSTA_DNEVNO) { await gostPostaIzcrpaj(oid); gostPostaDnevnik("testni", `[gost] dnevna meja gostujocih mailov (${GOST_POSTA_DNEVNO}): testni mail izpuscen (narocilo ${pre.public_ref})`); return false; }
    const ze = await pool.query("SELECT 1 FROM orders WHERE guest_email = $1 AND id <> $2 AND guest_mail_sent_at > NOW() - INTERVAL '24 hours' LIMIT 1", [pre.guest_email, oid]);
    if (ze.rows.length) { await gostPostaIzcrpaj(oid); console.error(`[gost] testni nacin: mail na isti naslov je bil ze poslan v 24 h, izpuscen (narocilo ${pre.public_ref})`); return false; }
  } else if (!brezplacno && dnevno >= GOST_POSTA_DNEVNO) {
    gostPostaDnevnik("placan", `[gost] opozorilo: ze ${dnevno} gostujocih mailov v 24 h (meja ${GOST_POSTA_DNEVNO} velja samo za testna narocila); potrdilo placanega narocila ${pre.public_ref} se poslje vseeno`, "warn");
  }
  const claimSql =
    `UPDATE orders SET guest_mail_attempts = guest_mail_attempts + 1, guest_mail_claimed_at = NOW()
      WHERE id = $1 AND guest_email IS NOT NULL AND status = 'paid' AND guest_mail_sent_at IS NULL AND guest_mail_attempts < $2
        AND (guest_mail_claimed_at IS NULL OR guest_mail_claimed_at < NOW() - ($3::bigint[])[guest_mail_attempts + 1] * INTERVAL '1 millisecond')
      RETURNING public_ref, guest_email, stripe_account_id, quantity, event_id, club_id, user_id, unit_price_cents, total_cents, currency, vat_rate, created_at, paid_at, guest_terms_version, guest_mail_attempts`;
  let k;
  if (!brezplacno) k = await pool.query(claimSql, [oid, GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
  else {
    // Brezplacno: stetje in rezervacija poskusa pod skupnim advisory zaklepom (kratko: brez Resenda), da hkratna posiljanja ne prideta mimo meje oba.
    // Steje poslane maile IN rezervirane (v teku) v zadnjih 24 h, drugih narocil za 0 EUR; vrstica pretekle ponovitve istega narocila se ne steje dvakrat.
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", ["gostposta:zastonj"]);
      const st = (await c.query(
        `SELECT COUNT(*)::int AS vse, COUNT(*) FILTER (WHERE kljuc = $2)::int AS naslov FROM (
           SELECT ${sqlNaslovKljuc("guest_email")} AS kljuc FROM orders
            WHERE id <> $1 AND guest_email IS NOT NULL AND total_cents = 0
              AND (guest_mail_sent_at > NOW() - INTERVAL '24 hours'
                   OR (guest_mail_sent_at IS NULL AND status = 'paid' AND guest_mail_claimed_at > NOW() - INTERVAL '24 hours'))) x`,
        [oid, naslovKljuc(pre.guest_email)])).rows[0];
      if (st.vse >= GOST_POSTA_ZASTONJ_DNEVNO || st.naslov >= GOST_POSTA_ZASTONJ_NA_NASLOV) {
        await c.query("UPDATE orders SET guest_mail_attempts = $2 WHERE id = $1 AND guest_mail_sent_at IS NULL", [oid, GOST_POSTA_POSKUSOV]);   // izpuscen: pospravljalec ga ne ponavlja
        await c.query("COMMIT");
        if (st.vse >= GOST_POSTA_ZASTONJ_DNEVNO) gostPostaDnevnik("zastonj-dnevno", `[gost] dnevna meja mailov gostom za 0 EUR (${GOST_POSTA_ZASTONJ_DNEVNO}): mail izpuscen (narocilo ${pre.public_ref})`);
        else gostPostaDnevnik("zastonj-naslov", `[gost] mail za 0 EUR: naslov je v 24 h ze dobil ${GOST_POSTA_ZASTONJ_NA_NASLOV} maile, izpuscen (narocilo ${pre.public_ref})`);
        return false;
      }
      k = await c.query(claimSql, [oid, GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
      await c.query("COMMIT");
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
    finally { c.release(); }
  }
  if (!k.rows.length) return false;
  const o = k.rows[0];
  const ev = await pool.query(
    `SELECT e.title AS event_title, e.start_at, e.min_age, cl.name AS club_name, cl.address AS club_address, cl.city AS club_city,
            cl.contact_phone AS club_phone, cl.contact_email AS club_email, ${SQL_PRODAJALEC_MAIL}, ${PRIZORISCE_MAIL_STOLPCI}
       FROM events e JOIN clubs cl ON cl.id = e.club_id ${PRIZORISCE_JOIN} WHERE e.id = $1`, [o.event_id]);
  if (!ev.rows.length) return false;
  const x = { ...o, ...ev.rows[0] };
  const zeton = o.user_id === null ? await gostKujZeton(pool, oid) : null;
  const prevzeto = zeton === null;   // narocilo je ze v racunu (zeton gosta je preklican): povezava vodi v /app/tickets
  const povezava = prevzeto ? `${placilaStripe.osnovaSpleta()}/app/tickets` : gostPovezava(zeton);
  // Kode QR kot vgrajene slike (CID) + PDF v prilogi (migracija 034): samo vstopnice, ki so SE vedno kupceve in veljavne (prevzeto naročilo je lahko
  // medtem delno preneseno: stara koda ne velja vec in je v mailu ne kazemo).
  const kv = (await pool.query(
    `SELECT t.serial, t.event_id, t.created_at FROM tickets t WHERE t.order_id = $1 AND t.status = 'valid' AND t.holder_user_id IS NULL AND NOT t.holder_is_guest ORDER BY t.id`, [oid])).rows;
  const kode = kv.map((t, i) => ({ cid: `ticket-qr-${i + 1}`, oznaka: kv.length > 1 ? `Ticket ${i + 1} of ${kv.length}` : "", n: i + 1, skupaj: kv.length, koda: qrVstopnice(t) }));
  const { besedilo, html } = gostPotrdilo(x, povezava, prevzeto, kode);
  const priloge = await prilogeVstopnic(x, kode.map(k => ({ ...k, vrsta: "Standard ticket" })), "outly-tickets.pdf");
  const r = await gostResendPosli({
    to: o.guest_email, subject: `Vaše vstopnice / Your tickets: ${x.event_title} (order ${o.public_ref})`.slice(0, 200), html, text: besedilo, attachments: priloge,
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
    await potrdiloPosljiNeposlane();   // potrdila kupcem z racunom (042, #95)
    await vraciloIzStripaPosljiNeposlane();   // vracila iz Stripove nadzorne plosce (053, #309)
  } catch (e) { console.error("[gost] pospravljanje mailov:", e && e.message); }
  finally { gostPostaTece = false; }
}
// ---------------------------
// POTRDILO O NAKUPU KUPCU Z RACUNOM — migracija 042, issue #95, invarianta I32
// ---------------------------
// Ko narocilo kupca Z RACUNOM postane `paid` (testni nacin in 0 EUR takoj ob nakupu, Stripe iz webhooka/pospravljalca prek `naPlacano` PO COMMIT-u),
// dobi kupec na e-naslov narocila (orders.buyer_email) potrdilo o sklenitvi pogodbe na trajnem nosilcu (ZVPot-1 132/6). Vzorec je gostov mail:
//   * natanko enkrat OB USPEHU: UPDATE ... RETURNING si rezervira poskus (receipt_mail_attempts, receipt_mail_claimed_at), receipt_mail_sent_at po uspehu Resenda;
//   * mnozica v teku (potrdiloVTeku) + spodnja meja premora (GOST_POSTA_PREMOR_MIN_MS) kot pri #201: pospravljalec ne prevzame narocila med pošiljanjem;
//   * Resend ob napaki ne vrze ({ error }): zapis v dnevnik brez e-naslova, ponovi pospravljalec z narascajocim premorom (GOST_POSTA_PREMORI, 8 poskusov).
// Dolgovano je SAMO, kjer koda postavi receipt_mail_attempts (= 0): nakup z racunom in zakljuci() za narocila z user_id. Guest lista, gostujoca narocila (imajo svoj mail
// z vstopnicami) in vsa stara narocila ostanejo NULL in potrdila ne dobijo. Od 20. 10. 2026 (Martin obrnil #95, DECISIONS) ima mail vgrajeno kodo QR prve vstopnice
// (CID) in PDF z vsemi kodami (vstopnica_priloge.js, kot gost); priprava je asinhrona, po COMMIT-u in pod semaforjem potrdil (I16), ob napaki gre mail brez priloge.
// Mail na izbrisan racun (buyer_email *@outly.invalid) se ne poslje. Za narocila brez placila (testni nacin, 0 EUR) velja meja POTRDILO_BREZ_PLACILA_NA_DAN na uporabnika na 24 h.
const POTRDILO_BREZ_PLACILA_NA_DAN = okoljeCelo("POTRDILO_BREZ_PLACILA_NA_DAN", 20, 1, 100000);
const potrdiloVTeku = new Set();
// Lasten, ozji semafor (2 sočasni) in vrsta za potrdila: mail z vstopnicami gostu je edini gostov dostop do vstopnic in ne sme cakati za mnozico potrdil
// (potrdilo je dodatek; ob preveliki vrsti ga prevzame pospravljalec). Skupaj z gostovim semaforjem (GOST_POSTA_SOCASNIH) je najvec 2 + 3 sočasnih klicev Resenda.
const POTRDILO_SOCASNIH = 2, POTRDILO_VRSTA_NAJVEC = 200;
const potrdiloPosta = { aktivnih: 0, cakajoci: [] };
async function potrdiloPostaVstopi() {
  if (potrdiloPosta.aktivnih < POTRDILO_SOCASNIH) { potrdiloPosta.aktivnih++; return true; }
  if (potrdiloPosta.cakajoci.length >= POTRDILO_VRSTA_NAJVEC) return false;
  await new Promise((r) => potrdiloPosta.cakajoci.push(r));
  return true;
}
function potrdiloPostaIzstopi() { const n = potrdiloPosta.cakajoci.shift(); if (n) n(); else potrdiloPosta.aktivnih--; }
const potrdiloIzcrpaj = (oid) => pool.query("UPDATE orders SET receipt_mail_attempts = $2 WHERE id = $1 AND receipt_mail_sent_at IS NULL", [oid, GOST_POSTA_POSKUSOV]);

// Vsebina potrdila kupcu (#95, kratka oblika od 20. 10. 2026: Martin je obrnil »brez QR«, DECISIONS 2026-10-20; besedilo po pravniku
// outly-hq/pravno/2026-10-20-potrdilo-nakupa-kratko.md, razdelek 6A platforma / 6B klub). Dvojezicno: slovenski blok (obvezen, ZVPot-1 7/1), locilo, angleski blok.
// Vsak blok: VRH (dogodek, datum, prizorisce, kolicina · znesek · plačano, starost + osebni dokument, kje je QR, stavek o prenosu, gumb, stevilka narocila) in
// DROBNI TISK (en odstavek, >= 12 px, #555 ali temneje, ni zlozen; isto besedilo v text/plain): neobstoj odstopa PRVI, zakonsko jamstvo, prodajalec (firma, sedez,
// telefon, e-naslov, maticna, davcna; stavek o DDV), pri klubu Outly kot posrednik, pritozbe, pogoji z razlicico. Nic pravnega ni samo na povezavi ali samo v PDF.
// pril = { kode: [{ cid }], vse: N vstopnic narocila, pdf: true|false } — PDF in vgrajena koda samo, ce je priprava uspela (sicer »vstopnice so v aplikaciji«, T4).
// T9: pri prodajalcu platformi (I50) besedilo ne govori o klubu (»organizator« / »prodajalec«).
const PLATFORMA_FIRMA = FIRMA_PLATFORME, PLATFORMA_SEDEZ = SEDEZ_PLATFORME;
const vstopnicSl = (n) => (n % 100 === 1 ? "vstopnica" : n % 100 === 2 ? "vstopnici" : n % 100 === 3 || n % 100 === 4 ? "vstopnice" : "vstopnic");
const LJ_KRATKO = new Intl.DateTimeFormat("sl-SI", { day: "numeric", month: "numeric", year: "numeric", timeZone: "Europe/Ljubljana" });
// Prodajalec v drobnem tisku (6A/6B). Vrne { besedilo, brezTelefona }. Pri platformi brez vpisane firme NEXT DIMENSIONS uporabi firmo in sedez iz POSREDNIK_VRSTICA.
function prodajalecKratko(o, jez) {
  const sl = jez === "sl";
  const s = prodajalec({ name: o.club_name, legal_name: o.legal_name, legal_address: o.legal_address, address: o.club_address, city: o.club_city,
    registration_number: o.registration_number, tax_number: o.tax_number, vat_payer: o.vat_payer, contact_phone: o.club_phone, contact_email: o.club_email });
  const platforma = o.stripe_account_id === placilaStripe.PLATFORMNI_RACUN;
  const lastnaFirma = !platforma || /next dimensions/i.test(s.name);
  const firma = lastnaFirma ? s.name : PLATFORMA_FIRMA;
  const sedez = lastnaFirma ? s.address : PLATFORMA_SEDEZ + (sl ? "" : ", Slovenia");
  const email = s.email || (platforma ? POSTA_ODGOVOR : "");
  const deli = [firma, sedez, s.phone ? `tel. ${s.phone}` : "", email,
    s.registration_number ? `${sl ? "matična št." : "company reg. no."} ${s.registration_number}` : "", s.tax_number ? `${sl ? "davčna št." : "tax no."} ${s.tax_number}` : ""].filter(Boolean);
  // Status DDV: davekStavek ga pove sam, ko stopnje ni (vat_rate NULL); ob vpisani stopnji ga dodamo, ce je znan.
  const status = o.vat_rate !== null && o.vat_rate !== undefined && s.vat_payer !== null
    ? ` ${s.vat_payer ? (sl ? "Prodajalec je zavezanec za DDV." : "The seller is a VAT payer.") : (sl ? "Prodajalec ni zavezanec za DDV." : "The seller is not a VAT payer.")}` : "";
  return { besedilo: `${sl ? "Prodajalec in organizator" : "Seller and organiser"}: ${deli.join(", ")}; ${davekStavek(o.vat_rate, s.vat_payer, jez)}${status}`, brezTelefona: !s.phone, platforma };
}
function kupecPotrdiloBloki(o, povezava, pril) {
  return JEZIKI_MAILA.map((jez) => {
    const T = (sl, en) => (jez === "sl" ? sl : en);
    const meja = starostZaPaket(o.min_age, !!o.package_name);
    const paket = meja > o.min_age;
    const jeMiza = !!o.table_label;
    const placilo = o.is_test ? T("testni nakup, nič ni bilo zaračunano", "test purchase, nothing was charged")
      : (o.total_cents === 0 ? T("brezplačno, nič ni bilo zaračunano", "free, nothing was charged") : T("plačano", "paid"));
    const kaj = jeMiza
      ? T(`VIP miza ${o.table_label} (${o.table_seats} ${sedezSl(o.table_seats)})${o.package_name ? `, paket ${o.package_name}` : ""}`,
          `VIP table ${o.table_label} (${o.table_seats} ${o.table_seats === 1 ? "seat" : "seats"})${o.package_name ? `, package ${o.package_name}` : ""}`)
      : T(`${o.quantity} ${vstopnicSl(o.quantity)}`, `${o.quantity} ${o.quantity === 1 ? "ticket" : "tickets"}`);
    const vrh = [ljDatum(o.start_at, jez), prizoriscePodatki(o), `${kaj} · ${znesek(o.total_cents, o.currency, jez)} · ${placilo}`];
    if (meja > 0) vrh.push(T(`Starost ${meja}+${paket ? " (miza s paketom pijače)" : ""}. Pri vhodu pokažite osebni dokument.`,
      `Age ${meja}+${paket ? " (table with a drinks package)" : ""}. Show a valid photo ID at the door.`));
    const n = pril.kode.length;
    const kode = pril.pdf && n
      ? [n > 1 ? T(`Kode QR so v priloženem PDF (outly-tickets.pdf, ena koda na stran) in v aplikaciji Outly (Profil → Vstopnice): ${povezava}`,
                   `Your QR codes are in the attached PDF (outly-tickets.pdf, one code per page) and in the Outly app (Profile, My tickets): ${povezava}`)
               : T(`Koda QR je v priloženem PDF (outly-tickets.pdf) in v aplikaciji Outly (Profil → Vstopnice): ${povezava}`,
                   `Your QR code is in the attached PDF (outly-tickets.pdf) and in the Outly app (Profile, My tickets): ${povezava}`),
         ...(n < pril.vse ? [T("V PDF so samo vstopnice, ki so še vaše (prenesenih ni).", "The PDF only contains the tickets that are still yours (not the ones you transferred).")] : []),
         T("Pri vhodu pokažite eno kodo na osebo.", "Show one code per person at the door.")]
      : [T(`Vstopnice s kodami QR so v aplikaciji Outly (Profil → Vstopnice): ${povezava}`, `Your tickets with QR codes are in the Outly app (Profile, My tickets): ${povezava}`),
         T("Pri vhodu pokažite eno kodo na osebo.", "Show one code per person at the door.")];
    const prenos = pril.pdf && n ? T("Če vstopnico v aplikaciji prenesete drugi osebi, njena koda QR v tem PDF-ju takoj preneha veljati; veljavna je samo koda v aplikaciji prejemnika.",
      "If you transfer a ticket in the app, its QR code in this PDF stops working immediately; only the code in the recipient's app is valid.") : null;
    const p = prodajalecKratko(o, jez);
    const drobni = [
      T("Pri vstopnicah za dogodek na določen datum nimate pravice do odstopa od pogodbe (ZVPot-1, 135. člen, 12. točka); ob odpovedi ali prestavitvi dogodka veljajo pogoji.",
        "There is no right of withdrawal for tickets to an event on a fixed date (Slovenian Consumer Protection Act ZVPot-1, Article 135, point 12); if the event is cancelled or postponed, the terms apply."),
      T("Za nepravilnosti pri izvedbi dogodka imate pravice po Zakonu o varstvu potrošnikov.", "You have the rights under the Consumer Protection Act if the event is not delivered as agreed."),
      p.besedilo,
      ...(p.platforma ? [] : [T(`Outly je samo posrednik: ${POSREDNIK_VRSTICA}.`, `Outly is only the intermediary: ${POSREDNIK_VRSTICA}.`)]),
      p.platforma ? T(`Pritožbe in vprašanja: odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR}.`, `Complaints and questions: reply to this email or write to ${POSTA_ODGOVOR}.`)
        : T(`Pritožbe glede dogodka: prodajalec; glede nakupa ali plačila: odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR}.`,
            `Complaints about the event: the seller; about the purchase or payment: reply to this email or write to ${POSTA_ODGOVOR}.`),
      o.terms_version ? T(`Pogoji uporabe Outly, različica ${o.terms_version}: https://outly.si/terms`, `Outly terms of use, version ${o.terms_version}: https://outly.si/terms`)
        : T("Pogoji uporabe Outly: https://outly.si/terms", "Outly terms of use: https://outly.si/terms"),
    ].join(" ");
    return {
      jez, naslov: T(`Vaše vstopnice za ${o.event_title}`, `Your tickets for ${o.event_title}`), vrh, kode, prenos,
      slika: jez === "sl" && pril.pdf && n ? { cid: pril.kode[0].cid, alt: T("Koda QR vstopnice", "Ticket QR code") } : null,
      gumb: T("Odpri v aplikaciji", "Open in the app"),
      narocilo: T(`Naročilo ${o.public_ref}, ${ljDatum(o.paid_at || o.created_at, jez)}.`, `Order ${o.public_ref}, ${ljDatum(o.paid_at || o.created_at, jez)}.`),
      drobni, brezTelefona: p.brezTelefona,
    };
  });
}
function kupecPotrdilo(o, povezava, pril = { kode: [], vse: 0, pdf: false }) {
  const bloki = kupecPotrdiloBloki(o, povezava, pril);
  const besedilo = bloki.map((b) => [b.naslov, "", ...b.vrh, "", ...b.kode, ...(b.prenos ? [b.prenos] : []), "", b.narocilo, "", b.drobni].join("\n")).join(`\n\n${LOCILO_MAILA}\n\n`) + "\n";
  const N = GOST_POSTA_NIZ;
  const zLinkom = (v) => { const e = N(v); return v.includes(povezava) ? e.replace(N(povezava), () => `<a href="${N(povezava)}" style="color:#111">${N(povezava)}</a>`) : e; };
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;line-height:1.45;color:#111;max-width:600px">` + bloki.map((b, i) =>
    (i ? `<hr style="margin:28px 0;border:0;border-top:1px solid #ccc">` : "") + `<div lang="${b.jez}">`
    + `<h2 style="margin:0 0 8px;font-size:20px">${N(b.naslov)}</h2>`
    + `<p style="margin:0 0 12px">${b.vrh.map((v, j) => (j === 2 ? `<strong>${N(v)}</strong>` : N(v))).join("<br>")}</p>`
    + (b.slika ? `<div style="margin:12px 0"><img src="cid:${b.slika.cid}" width="228" height="228" alt="${N(b.slika.alt)}" style="display:block;width:228px;height:228px;border:1px solid #ccc"></div>` : "")
    + b.kode.map((v) => `<p style="margin:0 0 6px">${zLinkom(v)}</p>`).join("")
    + (b.prenos ? `<p style="margin:0 0 6px"><strong>${N(b.prenos)}</strong></p>` : "")
    + `<p style="margin:16px 0"><a href="${N(povezava)}" style="display:inline-block;background:#111;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:bold">${N(b.gumb)}</a></p>`
    + `<p style="margin:0 0 12px">${N(b.narocilo)}</p>`
    + `<p style="margin:16px 0 0;font-size:13px;line-height:1.5;color:#555">${N(b.drobni)}</p>`
    + `</div>`).join("") + `</div>`;
  return { besedilo, html, brezTelefona: bloki[0].brezTelefona };
}
// Varnostni stavek v PDF kupca z racunom (angleski kot ves PDF; pravnik 2026-10-20, razdelek 5): prenos razveljavi kodo v PDF.
const QR_STAVEK_KUPEC = "One QR code is valid for one entry. If you transfer a ticket in the Outly app, its QR code in this PDF stops working immediately; only the code in the recipient's app is valid.";

async function posljiPotrdiloKupcu(oid) {
  if (!resend) return false;
  const kljuc = String(oid);   // kljuc mnozice vedno niz (kot gostVTeku)
  if (potrdiloVTeku.has(kljuc)) return false;
  potrdiloVTeku.add(kljuc);
  try {
    if (!(await potrdiloPostaVstopi())) return false;
    try { return await potrdiloPosljiEno(oid); }
    catch (err) { console.error(`Resend napaka (potrdilo kupcu, narocilo ${oid}):`, err && (err.message || String(err))); return false; }
    finally { potrdiloPostaIzstopi(); }
  } finally { potrdiloVTeku.delete(kljuc); }
}
// Vrstni red (#95 s PDF, 20. 10. 2026): preverbe -> podatki dogodka in TRENUTNE vstopnice kupca -> priprava QR/PDF (asinhrona, vstopnica_priloge.js; ob napaki POZOR in mail
// BREZ priloge, T4) -> rezervacija poskusa (claim) -> Resend. Priloga nastane PRED claimom: rok ponovnega prevzema (GOST_POSTA_TIMEOUT_MS + rezerva) tako pokriva samo klic
// Resenda, ne priprave PDF ob navali (sicer bi druga instanca narocilo prevzela med pripravo in poslala drugic). Vse to tece po COMMIT-u nakupa/webhooka, brez povezave
// iz poola med pripravo in pod semaforjem potrdil (2 socasni), zato nakup, webhook in sken ne cakajo nanj (I16).
// Kode QR: samo vstopnice, ki so se veljavne in KUPCEVE (holder NULL ali kupec, ne gost), s serialom ob posiljanju: prenesena vstopnica (nov serial je prejemnikov)
// v mailu NI, vstopnica, vrnjena kupcu, ima svoj trenutni serial.
async function potrdiloPosljiEno(oid) {
  const pre = (await pool.query(
    `SELECT user_id, status, buyer_email, guest_list_id, receipt_mail_attempts, receipt_mail_sent_at, public_ref, event_id, table_label, package_name,
            (COALESCE(stripe_payment_intent_id LIKE 'test_%', FALSE) OR total_cents = 0) AS brez_placila,
            (receipt_mail_claimed_at IS NULL OR receipt_mail_claimed_at < NOW() - ($1::bigint[])[COALESCE(receipt_mail_attempts, 0) + 1] * INTERVAL '1 millisecond') AS prevzemljivo
       FROM orders WHERE id = $2`, [GOST_POSTA_PREMORI, oid])).rows[0];
  if (!pre || pre.user_id === null || pre.guest_list_id !== null || pre.status !== "paid" || pre.receipt_mail_attempts === null
      || pre.receipt_mail_sent_at || pre.receipt_mail_attempts >= GOST_POSTA_POSKUSOV || !pre.prevzemljivo) return false;
  if (!/^[^@\s]+@[^@\s]+$/.test(pre.buyer_email || "") || /@outly\.invalid$/i.test(pre.buyer_email)) {
    await potrdiloIzcrpaj(oid);   // izbrisan racun: naslova ni vec
    return false;
  }
  // Meja za narocila BREZ placila (testni nacin, 0 EUR): mail gre sicer samo na naslov lastnega racuna, a brez placila ni dokaza resnosti nakupa.
  // Potrdilo resnicno placanega narocila (zakonska obveznost) se NIKOLI ne odlozi in ne izpusti.
  if (pre.brez_placila) {
    const ze = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE user_id = $1 AND receipt_mail_sent_at > NOW() - INTERVAL '24 hours'", [pre.user_id])).rows[0].n;
    if (ze >= POTRDILO_BREZ_PLACILA_NA_DAN) {
      await potrdiloIzcrpaj(oid);
      gostPostaDnevnik("potrdilo-brez-placila", `[potrdilo] meja ${POTRDILO_BREZ_PLACILA_NA_DAN} potrdil na uporabnika na 24 h za narocila brez placila: potrdilo izpuscen (narocilo ${pre.public_ref})`);
      return false;
    }
  }
  const ev = (await pool.query(
    `SELECT e.title AS event_title, e.start_at, e.min_age, e.club_id, cl.name AS club_name, cl.address AS club_address, cl.city AS club_city,
            cl.contact_phone AS club_phone, cl.contact_email AS club_email, ${SQL_PRODAJALEC_MAIL}, ${PRIZORISCE_MAIL_STOLPCI}
       FROM events e JOIN clubs cl ON cl.id = e.club_id ${PRIZORISCE_JOIN} WHERE e.id = $1`, [pre.event_id])).rows[0];
  if (!ev) return false;
  const vs = (await pool.query(
    `SELECT t.serial, t.event_id, t.created_at, (t.status = 'valid' AND NOT t.holder_is_guest AND (t.holder_user_id IS NULL OR t.holder_user_id = $2)) AS kupceva
       FROM tickets t WHERE t.order_id = $1 ORDER BY t.id`, [oid, pre.user_id])).rows;
  const kv = vs.filter((t) => t.kupceva);
  const kode = kv.map((t, i) => ({ cid: `ticket-qr-${i + 1}`, oznaka: kv.length > 1 ? `Ticket ${i + 1} of ${kv.length}` : "", n: i + 1, skupaj: kv.length, koda: qrVstopnice(t) }));
  let priloge = [];
  if (kode.length) {
    try {
      const meja = starostZaPaket(ev.min_age, !!pre.package_name);
      priloge = await prilogeVstopnic({ ...ev, starostPdf: meja > 0 ? `Age limit: ${meja}+. Show a valid photo ID at the door.` : "" },
        kode.map((k) => ({ ...k, vrsta: pre.table_label ? `VIP table ${pre.table_label}` : "Standard ticket" })), "outly-tickets.pdf", QR_STAVEK_KUPEC);
    } catch (e) {
      priloge = [];
      console.error(`[potrdilo] POZOR: priprava QR/PDF za narocilo ${pre.public_ref} ni uspela (${e && e.message}); potrdilo gre BREZ priloge (vstopnice so v aplikaciji)`);
    }
  }
  const k = await pool.query(
    `UPDATE orders SET receipt_mail_attempts = receipt_mail_attempts + 1, receipt_mail_claimed_at = NOW()
      WHERE id = $1 AND user_id IS NOT NULL AND guest_list_id IS NULL AND status = 'paid' AND receipt_mail_sent_at IS NULL
        AND receipt_mail_attempts IS NOT NULL AND receipt_mail_attempts < $2
        AND (receipt_mail_claimed_at IS NULL OR receipt_mail_claimed_at < NOW() - ($3::bigint[])[receipt_mail_attempts + 1] * INTERVAL '1 millisecond')
      RETURNING public_ref, buyer_email, stripe_account_id, quantity, event_id, unit_price_cents, total_cents, currency, vat_rate, created_at, paid_at,
                table_label, table_seats, package_name, receipt_mail_attempts, terms_version, COALESCE(stripe_payment_intent_id LIKE 'test_%', FALSE) AS is_test`,
    [oid, GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
  if (!k.rows.length) return false;
  const o = k.rows[0];
  const x = { ...o, ...ev };
  const zPdf = priloge.length > 0;
  const { besedilo, html, brezTelefona } = kupecPotrdilo(x, `${placilaStripe.osnovaSpleta()}/app/tickets`, { kode: zPdf ? kode : [], vse: vs.length, pdf: zPdf });
  // T2 (pravnik 20. 10. 2026, ZVPot-1 130/1-1): telefon prodajalca je obvezen, I34 pa pusti nakup tudi samo z e-naslovom. Ne izpuscamo tiho: alarm (najvec 1/h).
  if (brezTelefona) gostPostaDnevnik("potrdilo-brez-telefona", `[potrdilo] POZOR: prodajalec (klub ${ev.club_id}) nima telefona: potrdilo narocila ${o.public_ref} je brez telefona prodajalca (ZVPot-1 130/1-1); vpisi telefon v podatke prodajalca`);
  const r = await gostResendPosli({ to: o.buyer_email, subject: `Vaše vstopnice / Your tickets: ${x.event_title}, ${LJ_KRATKO.format(new Date(x.start_at))} (${o.public_ref})`.slice(0, 200),
    html, text: besedilo, attachments: zPdf ? priloge : undefined });
  if (r && r.error) {
    console.error(`Resend napaka (potrdilo kupcu, ${o.public_ref}, poskus ${o.receipt_mail_attempts}/${GOST_POSTA_POSKUSOV}):`, JSON.stringify(r.error));
    if (o.receipt_mail_attempts >= GOST_POSTA_POSKUSOV) console.error(`[potrdilo] POZOR: potrdilo za narocilo ${o.public_ref} NI mogoce poslati (izcrpanih ${GOST_POSTA_POSKUSOV} poskusov); kupec ima vstopnice v aplikaciji, potrdila po e-posti pa ne`);
    return false;
  }
  await pool.query("UPDATE orders SET receipt_mail_sent_at = NOW() WHERE id = $1", [oid]);
  console.log(`[potrdilo] mail kupcu poslan: narocilo ${o.public_ref}${zPdf ? `, PDF ${kode.length}` : ", brez priloge"}`);
  return true;
}
// Pospravljalec: placana narocila z racunom brez poslanega potrdila (Resend je padel, proces se je ugasnil med placilom in mailom).
async function potrdiloPosljiNeposlane() {
  if (!resend) return;
  const r = await pool.query(
    `SELECT id FROM orders WHERE receipt_mail_attempts IS NOT NULL AND receipt_mail_sent_at IS NULL AND status = 'paid' AND user_id IS NOT NULL
        AND receipt_mail_attempts < $1 AND paid_at > NOW() - INTERVAL '3 days'
        AND (receipt_mail_claimed_at IS NULL OR receipt_mail_claimed_at < NOW() - ($2::bigint[])[receipt_mail_attempts + 1] * INTERVAL '1 millisecond')
      ORDER BY id LIMIT 20`, [GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
  for (const o of r.rows) await posljiPotrdiloKupcu(o.id);
}
// ---------------------------
// VRACILA IN SPORI — OBVESTILA (issue #190, migracija 047, vracila_stripe.js)
// ---------------------------
// Trije maili kupcu (vsak natanko enkrat): `odpoved` (»na poti«), `vrnjeno` (»vrnili smo«) in od #251 (migracija 051) `ni_izvedeno` (Stripe je vracilo zavrnil, kupec denarja ni dobil).
// Kupec ob ODPOVEDI DOGODKA dobi mail, ko je vracilo opravljeno (besedilo mora biti resnicno: »vrnjeno«, ne »bomo vrnili«). Vzorec kot gostov mail in potrdilo kupcu:
//   * natanko enkrat OB USPEHU: UPDATE ... RETURNING si rezervira poskus (vracila.mail_poskusi, mail_prevzeto_at), mail_poslano_at po uspehu Resenda;
//   * Resend ob napaki NE vrze ({ error }): zapis v dnevnik brez e-naslova, ponovi obdelovalec z narascajocim premorom (GOST_POSTA_PREMORI, 8 poskusov);
//   * posilja ga SAMO obdelovalec (vracilaObvestilaNeposlana, po vrsti z razmikom): 1000 hkratnih mailov bi presegli Resendovo omejitev (2 zahtevka/s).
// Prejemnik je orders.buyer_email (kupec z racunom: naslov racuna; gost: naslov nakupa). Izbrisan racun / anonimiziran gost (*@outly.invalid) ne dobi maila.
// Brezplacno (0 EUR) in testno narocilo: mail pove, da se ni zaracunalo nic. Mail ne vsebuje kod QR ali povezave do vstopnic (vstopnice po odpovedi ne veljajo).
const VRACILA_MAIL_RAZMAK_MS = okoljeCelo("VRACILA_MAIL_RAZMAK_MS", 550, 0, 60000);
// Mail `ni_izvedeno` (#251) gre sele, ko je Stripe vracilo zavrnil in je vrstica v ni_uspelo/rocno vsaj toliko casa (ni_izvedeno_od_at). Samo blazilnik
// (pravnik 17. 10. 2026: zavrnjenega Stripovega vracila admin ne more ponoviti, retry je 409, zato dolgo cakanje nima smisla).
const VRACILA_NI_IZVEDENO_PO_MS = okoljeCelo("VRACILA_NI_IZVEDENO_PO_MS", 3600 * 1000, 0, 30 * 24 * 3600 * 1000);
const VRACILA_MAIL_PAKET = 20;
// #285: mail `ni_izvedeno` (»uredili ga bomo rocno«) gre SAMO ob stanjih spora, kjer kupec denarja ne dobi vec prek banke ali spor ni chargeback (WHITELIST, ne seznam odprtih):
// won, warning_closed, prevented (spor zakljucen v korist trgovca), warning_needs_response / warning_under_review (poizvedba banke, ni chargeback; pravnikov rok 1 h velja),
// charge_refunded (vracilo ustavi kupecVrnjenPredMailom) in `lost` (tega obravna posljiVraciloKupcu: mail NE gre, POZOR). Vse drugo (needs_response, under_review, unknown, karkoli novega) mail ODLOZI
// brez casovne meje (admin vidi vrstico ni_uspelo v seznamu pozornosti in stevec sporov). Spor se veze po order_id ALI po PaymentIntentu (spor brez order_id: narocilo ni imelo PI).
const SPORI_MAIL_SME_SQL = "'won', 'warning_closed', 'prevented', 'warning_needs_response', 'warning_under_review', 'charge_refunded', 'lost'";
const vraciloMailVTeku = new Set();
// vrsta: 'odpoved' (takoj po zamiku odpovedi: »dogodek odpovedan, vracilo je na poti«; 0 EUR/test: »nic ni bilo zaracunano«) | 'vrnjeno' (Stripe je vracilo IZVEDEL: »vrnili smo«;
// razlog inactive_order: »placilo smo vrnili, naroceno ni bilo zakljuceno«). Martin 12. 10. 2026: oba maila, natanko enkrat vsak.
// | 'ni_izvedeno' (#251, besedilo pravnik 17. 10. 2026: Stripe je vracilo ZAVRNIL (failed/canceled), vrstica je v ni_uspelo/rocno, kupec denarja NI dobil;
// po VRACILA_NI_IZVEDENO_PO_MS, pri event_cancelled sele po mailu 'odpoved'; tudi kot popravek, ce je kupec prej dobil »vrnili smo«, Stripe pa je vracilo nato zavrnil).
// »celoten znesek / the full amount« samo, kadar je znesek vracila enak placanemu (total_cents); pri delno ze vrnjenem narocilu samo »znesek / the amount«.
function vraciloMailBesedilo(o, vrsta) {
  return izrisiDvojezicno((jez) => {
    const T = (sl, en) => (jez === "sl" ? sl : en);
    const jeMiza = !!o.table_label;
    const kaj = jeMiza ? T(`VIP miza ${o.table_label}`, `VIP table ${o.table_label}`)
      : T(`${o.quantity} ${o.quantity === 1 ? "vstopnica" : "vstopnice"}`, `${o.quantity} ${o.quantity === 1 ? "ticket" : "tickets"}`);
    const zn = znesek(o.znesek_cents, o.currency, jez);
    const koncno = vrsta === "vrnjeno";
    const platforma = o.stripe_account_id === placilaStripe.PLATFORMNI_RACUN;   // I50: prodajalec je platforma, »organizatorja« ni (ni tretje stranke)
    if (vrsta === "ni_izvedeno") {
      const ec = o.razlog !== "inactive_order";
      return {
        naslovBesedila: T(`Vračilo še ni izvedeno - naročilo ${o.public_ref}`, `Refund not completed yet - order ${o.public_ref}`),
        naslovHtml: T("Vračilo še ni izvedeno", "Refund not completed yet"),
        razdelki: [
          ...(ec ? [{ naslov: T("Dogodek", "Event"), vrstice: [
            T(`Dogodek »${o.event_title}« (${ljDatum(o.start_at, jez)}) je odpovedan.`, `The event "${o.event_title}" (${ljDatum(o.start_at, jez)}) has been cancelled.`),
            T(`Naročilo ${o.public_ref}: ${kaj}.`, `Order ${o.public_ref}: ${kaj}.`)] }] : []),
          { naslov: T("Vračilo", "Refund"), krepko: true, vrstice: ec ? [
            T(`Ob odpovedi dogodka smo ${platforma ? "" : "v imenu organizatorja "}sprožili vračilo ${zn} na način plačila, s katerim ste plačali. Ponudnik plačilnih storitev vračila ni izvedel, zato denarja še niste prejeli.`,
              `When the event was cancelled, we started a refund of ${zn} to the payment method you used${platforma ? "" : ", on the organiser's behalf"}. The payment provider did not complete the refund, so you have not received the money yet.`),
            T(`Do vračila ste še vedno upravičeni. Uredili ga bomo ročno${platforma ? "" : ", skupaj z organizatorjem"}.`,
              `You are still entitled to the refund. We will arrange it manually${platforma ? "" : ", together with the organiser"}.`)] : [
            T(`Vračila vašega plačila ${zn} za naročilo ${o.public_ref} (dogodek »${o.event_title}«), ki ni bilo zaključeno, ponudnik plačilnih storitev ni izvedel, zato denarja še niste prejeli.`,
              `The payment provider did not complete the refund of your payment of ${zn} for order ${o.public_ref} (event "${o.event_title}"), which was not completed, so you have not received the money yet.`),
            T("Do vračila ste še vedno upravičeni. Uredili ga bomo ročno.", "You are still entitled to the refund. We will arrange it manually.")] },
          { naslov: T("Kaj lahko storite", "What you can do"), vrstice: [
            T("Zdaj vam ni treba storiti ničesar. Če ste kartico ali račun, s katerim ste plačali, medtem zaprli ali zamenjali, nam to sporočite z odgovorom na to sporočilo. Če bomo za vračilo potrebovali kakšen podatek, vam pišemo na ta elektronski naslov. Za vračilo vas nikoli ne bomo prosili za številko kartice, kodo ali geslo.",
              "You don't need to do anything right now. If you have closed or replaced the card or account you paid with, let us know by replying to this email. If we need any details to complete the refund, we will write to you at this email address. We will never ask for your card number, a code or a password for a refund.")] },
          { naslov: T("Vprašanja", "Questions"), vrstice: [
            T(`Glede vračila odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR} in navedite naročilo ${o.public_ref}. Glede dogodka se obrnite na klub (${o.club_name}).`,
              `About the refund, reply to this email or write to ${POSTA_ODGOVOR} and quote order ${o.public_ref}. About the event, contact the club (${o.club_name}).`)] },
        ],
      };
    }
    const celoten = o.znesek_cents === o.total_cents;   // delno ze vrnjeno narocilo: vracamo ostanek, ne »celoten znesek«
    const vseVrnjeno = (o.skupaj_vrnjeno_cents ?? o.znesek_cents) >= o.total_cents;   // iz_stripa: po tem vracilu je vrnjeno vse (vstopnice ne veljajo)
    if (vrsta === "iz_stripa") {   // #309: vracilo, narejeno v Stripovi nadzorni plosci (ne odpoved dogodka); delno vracilo: vstopnice ostanejo veljavne (uveljaviVracilo)
      return {
        naslovBesedila: T(`Vračilo opravljeno - naročilo ${o.public_ref}`, `Refund completed - order ${o.public_ref}`), naslovHtml: T("Vračilo opravljeno", "Refund completed"),
        razdelki: [
          { naslov: T("Naročilo", "Order"), vrstice: [T(`Naročilo ${o.public_ref}: ${kaj}, dogodek »${o.event_title}« (${ljDatum(o.start_at, jez)}).`,
            `Order ${o.public_ref}: ${kaj}, event "${o.event_title}" (${ljDatum(o.start_at, jez)}).`)] },
          { naslov: T("Vračilo", "Refund"), krepko: true, vrstice: [
            T(`Vrnili smo vam ${celoten ? "celoten znesek" : "znesek"} ${zn} na način plačila, s katerim ste plačali. Banka ga običajno knjiži v 5 do 10 delovnih dneh.`,
              `We have refunded ${celoten ? "the full amount" : "the amount"} of ${zn} to the payment method you used. Your bank usually posts it within 5 to 10 business days.`),
            ...(celoten ? [] : [vseVrnjeno
              ? T(`S tem je vrnjen celoten znesek naročila (${znesek(o.total_cents, o.currency, jez)}).`, `The full amount of the order (${znesek(o.total_cents, o.currency, "en")}) has now been refunded.`)
              : T(`Skupaj je za to naročilo vrnjeno ${znesek(o.skupaj_vrnjeno_cents, o.currency, jez)} od ${znesek(o.total_cents, o.currency, jez)}.`,
                  `In total, ${znesek(o.skupaj_vrnjeno_cents, o.currency, "en")} of ${znesek(o.total_cents, o.currency, "en")} has been refunded for this order.`)]),
            vseVrnjeno ? T("Vstopnice tega naročila ne veljajo več.", "The tickets of this order are no longer valid.")
              : T("Vstopnice tega naročila ostanejo veljavne.", "The tickets of this order remain valid.")] },
          { naslov: T("Vprašanja", "Questions"), vrstice: [platforma
            ? T(`Odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR} in navedite naročilo ${o.public_ref}.`, `Reply to this email or write to ${POSTA_ODGOVOR} and quote order ${o.public_ref}.`)
            : T(`Glede vračila odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR} in navedite naročilo ${o.public_ref}. Glede dogodka se obrnite na klub (${o.club_name}).`,
              `About the refund, reply to this email or write to ${POSTA_ODGOVOR} and quote order ${o.public_ref}. About the event, contact the club (${o.club_name}).`)] },
        ],
      };
    }
    if (o.razlog === "inactive_order") {
      return {
        naslovBesedila: T(`Plačilo vrnjeno - naročilo ${o.public_ref}`, `Payment refunded - order ${o.public_ref}`), naslovHtml: T("Plačilo vrnjeno", "Payment refunded"),
        razdelki: [
          { naslov: T("Naročilo", "Order"), vrstice: [T(`Vaše plačilo ${zn} za naročilo ${o.public_ref} (dogodek »${o.event_title}«) smo vrnili, ker naročilo ni bilo zaključeno in zato niste prejeli vstopnic.`,
            `We have refunded your payment of ${zn} for order ${o.public_ref} (event "${o.event_title}"): the order was not completed, so no tickets were issued.`)], krepko: true },
          { naslov: T("Vračilo", "Refund"), vrstice: [T("Znesek je šel na način plačila, s katerim ste plačali. Banka ga običajno knjiži v 5 do 10 delovnih dneh. Če še vedno želite vstopnice, naročilo ponovite.",
            "The money went back to the payment method you used. Your bank usually posts it within 5 to 10 business days. If you still want tickets, please place the order again.")] },
          { naslov: T("Vprašanja", "Questions"), vrstice: [T(`Odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR}.`, `Reply to this email or write to ${POSTA_ODGOVOR}.`)] },
        ],
      };
    }
    const vrstice = o.brez_placila
      ? [T("Za to naročilo ni bilo zaračunano nič (brezplačno ali testno naročilo), zato vračilo ni potrebno. Vstopnice zanj ne veljajo več.",
           "Nothing was charged for this order (free or test order), so no refund is needed. The tickets no longer apply.")]
      : koncno
        ? [T(`Vrnili smo vam ${celoten ? "celoten znesek" : "znesek"} ${zn} na način plačila, s katerim ste plačali. Banka ga običajno knjiži v 5 do 10 delovnih dneh.`,
             `We have refunded ${celoten ? "the full amount" : "the amount"} of ${zn} to the payment method you used. Your bank usually posts it within 5 to 10 business days.`),
           T("Vstopnice za ta dogodek ne veljajo več.", "The tickets for this event are no longer valid.")]
        : [T(`${celoten ? "Celoten znesek" : "Znesek"} ${zn} vam vrnemo na način plačila, s katerim ste plačali. Vračilo je v teku; ko bo opravljeno, vam pošljemo še eno sporočilo. Banka ga običajno knjiži v 5 do 10 delovnih dneh.`,
             `We are refunding ${celoten ? "the full amount" : "the amount"} of ${zn} to the payment method you used. The refund is in progress; we will send you another email when it is done. Your bank usually posts it within 5 to 10 business days.`),
           T("Vstopnice za ta dogodek ne veljajo več. Vračilo sprožimo samodejno. Če bo ponudnik plačilnih storitev za izvedbo vračila potreboval dodaten korak ali vaše podatke, vam bo poslal navodila; sledite jim, sicer vračilo morda ne bo izvedeno. Za vračilo vas nikoli ne bomo prosili za številko kartice ali geslo.", "The tickets for this event are no longer valid. We start the refund automatically. If the payment provider needs an extra step or your details to complete the refund, it will send you instructions; please follow them, otherwise the refund may not go through. We will never ask for your card number or password for a refund.")];
    return {
      naslovBesedila: koncno ? T(`Vračilo opravljeno - naročilo ${o.public_ref}`, `Refund completed - order ${o.public_ref}`) : T(`Dogodek je odpovedan - naročilo ${o.public_ref}`, `Event cancelled - order ${o.public_ref}`),
      naslovHtml: koncno ? T("Vračilo opravljeno", "Refund completed") : T("Dogodek je odpovedan", "Event cancelled"),
      razdelki: [
        { naslov: T("Dogodek", "Event"), vrstice: [T(`Dogodek »${o.event_title}« (${ljDatum(o.start_at, jez)}) je odpovedan.`, `The event "${o.event_title}" (${ljDatum(o.start_at, jez)}) has been cancelled.`),
          T(`Naročilo ${o.public_ref}: ${kaj}.`, `Order ${o.public_ref}: ${kaj}.`)] },
        { naslov: T("Vračilo", "Refund"), vrstice, krepko: !o.brez_placila },
        { naslov: T("Vprašanja", "Questions"), vrstice: [T(`Glede dogodka se obrnite na klub (${o.club_name}), glede vračila odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR}.`,
          `About the event, contact the club (${o.club_name}); about the refund, reply to this email or write to ${POSTA_ODGOVOR}.`)] },
      ],
    };
  });
}
// Skupno pošiljanje: stolpci za vrsto maila. Claim v bazi (natanko enkrat OB USPEHU) + množica v teku.
const VRACILO_MAIL = {
  odpoved: { poskusi: "mail_odpoved_poskusi", prevzeto: "mail_odpoved_prevzeto_at", poslano: "mail_odpoved_poslano_at",
    pogoj: "v.razlog = 'event_cancelled' AND v.stanje <> 'preklicano' AND v.mail_odpoved_po_at <= NOW() AND EXISTS (SELECT 1 FROM events ev WHERE ev.id = v.event_id AND ev.status = 'cancelled')",
    zadeva: "Dogodek odpovedan / Event cancelled" },
  vrnjeno: { poskusi: "mail_poskusi", prevzeto: "mail_prevzeto_at", poslano: "mail_poslano_at",
    // tudi `rocno` / `ni_uspelo` po USPELEM koraku A (npr. vracila provizije ni mogoce izracunati): kupec je denar dobil, mail mu pripada
    pogoj: "NOT v.brez_stripa AND (v.stanje = 'opravljeno' OR (v.stanje IN ('rocno', 'ni_uspelo') AND v.stripe_vracilo_id IS NOT NULL AND v.stripe_stanje = 'succeeded'))",
    zadeva: "Vračilo / Refund" },
  // #251 (pogoj pravnik 17. 10. 2026): SAMO ob znani Stripovi zavrnitvi (stripe_stanje failed/canceled) v ni_uspelo/rocno. Brez stripe_stanje (rocno po sesutju, napaka API)
  // ne vemo, ali je denar odsel: samo obstojeci alarm. Ne pending/requires_action/succeeded (`potrditev`, `vrnjeno`), ne brez_stripa / 0 EUR / testno (test_ PI) / preklicano.
  // Vsaj VRACILA_NI_IZVEDENO_PO_MS od ni_izvedeno_od_at; pri event_cancelled sele po poslanem mailu `odpoved` (inactive_order ga nima) in samo, ce je dogodek se odpovedan.
  // Tik pred Resendom posljiVraciloKupcu vprasa Stripe (vracilaStripe.kupecVrnjenPredMailom), ali je kupec medtem rocno vrnjen v nadzorni plosci.
  // Pogoj vsebuje pogoj indeksa vracila_mail_ni_izvedeno_idx (051: NOT brez_stripa, stanje, stripe_stanje, mail_ni_izvedeno_poslano_at IS NULL); ob spremembi uskladi oba.
  // #285: spor, ki NI v SPORI_MAIL_SME_SQL (pravi chargeback ali neznano stanje), mail ODLOZI (pogoj ni resnicen: brez claima, poskus se ne porabi, vrstica ostane odprta); `lost` obravna posljiVraciloKupcu.
  ni_izvedeno: { poskusi: "mail_ni_izvedeno_poskusi", prevzeto: "mail_ni_izvedeno_prevzeto_at", poslano: "mail_ni_izvedeno_poslano_at",
    pogoj: `NOT v.brez_stripa AND v.stanje IN ('ni_uspelo', 'rocno') AND v.stripe_stanje IN ('failed', 'canceled')
      AND v.ni_izvedeno_od_at <= NOW() - (${VRACILA_NI_IZVEDENO_PO_MS}::bigint * INTERVAL '1 millisecond')
      AND (v.razlog = 'inactive_order' OR (v.mail_odpoved_poslano_at IS NOT NULL AND EXISTS (SELECT 1 FROM events ev WHERE ev.id = v.event_id AND ev.status = 'cancelled')))
      AND NOT COALESCE(v.payment_intent_id LIKE 'test_%', FALSE)
      AND EXISTS (SELECT 1 FROM orders zo WHERE zo.id = v.order_id AND zo.total_cents > 0 AND NOT COALESCE(zo.stripe_payment_intent_id LIKE 'test_%', FALSE))
      AND NOT EXISTS (SELECT 1 FROM spori sp WHERE (sp.order_id = v.order_id OR sp.payment_intent_id = v.payment_intent_id) AND sp.stanje NOT IN (${SPORI_MAIL_SME_SQL}))`,
    zadeva: "Vračilo še ni izvedeno / Refund not completed yet" },
};
async function posljiVraciloKupcu(vid, vrsta) {
  if (!resend) return false;
  const m = VRACILO_MAIL[vrsta];
  const kljuc = `${vid}:${vrsta}`;
  if (vraciloMailVTeku.has(kljuc)) return false;
  if (vrsta === "ni_izvedeno" && !vracilaStripe.preverbaNaVoljo()) return false;   // preverba pri Stripu je omejena na tek: ostale v naslednjem teku (brez claima)
  vraciloMailVTeku.add(kljuc);
  try {
    const k = await pool.query(
      `UPDATE vracila v SET ${m.poskusi} = v.${m.poskusi} + 1, ${m.prevzeto} = NOW()
        WHERE v.id = $1 AND ${m.pogoj} AND v.${m.poslano} IS NULL AND v.${m.poskusi} < $2
          AND (v.${m.prevzeto} IS NULL OR v.${m.prevzeto} < NOW() - ($3::bigint[])[v.${m.poskusi} + 1] * INTERVAL '1 millisecond')
        RETURNING v.order_id, v.payment_intent_id, v.razlog, v.znesek_cents, v.valuta, v.${m.poskusi} AS poskus`, [vid, GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
    if (!k.rows.length) return false;
    const v = k.rows[0];
    const r0 = await pool.query(
      `SELECT o.public_ref, o.buyer_email, o.quantity, o.currency, o.table_label, o.total_cents, o.refunded_cents, e.title AS event_title, e.start_at, cl.name AS club_name,
              o.stripe_account_id,
              (o.total_cents = 0 OR COALESCE(o.stripe_payment_intent_id LIKE 'test_%', FALSE)) AS brez_placila
         FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = e.club_id WHERE o.id = $1`, [v.order_id]);
    const o = r0.rows[0];
    if (!o) return false;
    if (vrsta === "ni_izvedeno") {   // #285: spor `lost` = kupec je denar ze dobil prek banke (chargeback): obljuba »uredili ga bomo rocno« bi bila napacna in admina zapeljala v dvojno vracilo
      const lost = await pool.query("SELECT COALESCE(SUM(znesek_cents), 0)::bigint AS cents FROM spori WHERE (order_id = $1 OR ($2::text IS NOT NULL AND payment_intent_id = $2)) AND stanje = 'lost' HAVING COUNT(*) > 0", [v.order_id, v.payment_intent_id]);
      if (lost.rows.length) {
        await pool.query(`UPDATE vracila SET ${m.poskusi} = $2 WHERE id = $1 AND ${m.poslano} IS NULL`, [vid, GOST_POSTA_POSKUSOV]);   // obdelano: brez zanke, brez maila
        const placano = v.znesek_cents !== null && v.znesek_cents !== undefined ? v.znesek_cents : Math.max(0, o.total_cents - (o.refunded_cents || 0)), spor = Number(lost.rows[0].cents);
        console.error(`[vracila] POZOR: narocilo ${o.public_ref} (vracilo ${vid}): Stripe vracila ni izvedel, kupec pa je denar dobil prek izgubljenega spora (chargeback); mail »vracilo se ni izvedeno« NI poslan. `
          + (spor < placano ? `DELNI spor: ${spor} od ${placano} centov - razliko preveri rocno.` : "NE vracaj rocno (dvojno vracilo)."));
        return false;
      }
    }
    const naslovIzbrisan = /@outly\.invalid$/i.test(o.buyer_email || "");
    if (!/^[^@\s]+@[^@\s]+$/.test(o.buyer_email || "") || naslovIzbrisan) {
      await pool.query(`UPDATE vracila SET ${m.poskusi} = $2 WHERE id = $1 AND ${m.poslano} IS NULL`, [vid, GOST_POSTA_POSKUSOV]);   // naslova ni vec: ne ponavljaj
      // #285: claim zahteva poskusi < max, po tem zapisu je poskusi = max: ta vrstica pride sem NATANKO ENKRAT, zato je alarm enkraten (brez e-naslova: osebni podatki ostanejo v bazi)
      if (vrsta === "ni_izvedeno") console.error(`[vracila] POZOR: kupec narocila ${o.public_ref} ni obvescen o neuspelem vracilu (${naslovIzbrisan ? "naslov izbrisan" : "naslov neveljaven"}) - obvesti/rocno`);
      return false;
    }
    // pred prvim poskusom znesek se ni zamrznjen: kar je se placano (obdelovalec bo vrnil ostanek, vracila_stripe.js izvedi())
    const zn = v.znesek_cents !== null && v.znesek_cents !== undefined ? v.znesek_cents : Math.max(0, o.total_cents - (o.refunded_cents || 0));
    if (vrsta === "ni_izvedeno") {   // je kupec medtem vseeno dobil denar (rocno vracilo v Stripovi plosci)? Raje zamuda kot napacen mail.
      const izid = await vracilaStripe.kupecVrnjenPredMailom(vid);
      // claim sprosti brez porabe poskusa, a NE pod 1: premor GOST_POSTA_PREMORI[1] (2 min) od prevzema, ne klic Stripa vsak tek
      if (izid === "neznano") { await pool.query(`UPDATE vracila SET ${m.poskusi} = GREATEST(${m.poskusi} - 1, 1) WHERE id = $1 AND ${m.poslano} IS NULL`, [vid]); return false; }
      // vracilo na poti: prvih 24 h kot 'neznano' (premor 2 min); potem poskus OSTANE porabljen (premor raste po GOST_POSTA_PREMORI do ~24 h), a nikoli do max (mail ostane mogoc)
      if (izid === "na_poti") {
        await pool.query(`UPDATE vracila SET ${m.poskusi} = CASE WHEN ni_izvedeno_od_at < NOW() - INTERVAL '24 hours' THEN LEAST(${m.poskusi}, $2::int - 1) ELSE GREATEST(${m.poskusi} - 1, 1) END
                           WHERE id = $1 AND ${m.poslano} IS NULL`, [vid, GOST_POSTA_POSKUSOV]);
        return false;
      }
      if (izid !== "poslji") {
        if (izid === "ne") await pool.query(`UPDATE vracila SET ${m.poskusi} = $2 WHERE id = $1 AND ${m.poslano} IS NULL`, [vid, GOST_POSTA_POSKUSOV]);   // trajno: ne ponavljaj
        return false;
      }
    }
    const { besedilo, html } = vraciloMailBesedilo({ ...o, currency: v.valuta || o.currency, razlog: v.razlog, znesek_cents: zn }, vrsta);   // #285 N3: valuta vracila (seja) ima prednost pred valuto naroceno
    const r = await gostResendPosli({ to: o.buyer_email, subject: `${m.zadeva}: ${o.event_title} (${o.public_ref})`.slice(0, 200), html, text: besedilo });
    if (r && r.error) {
      console.error(`Resend napaka (vracilo kupcu ${vrsta}, ${o.public_ref}, poskus ${v.poskus}/${GOST_POSTA_POSKUSOV}):`, JSON.stringify(r.error));
      if (v.poskus >= GOST_POSTA_POSKUSOV) console.error(`[vracila] POZOR: obvestila (${vrsta}) za narocilo ${o.public_ref} NI mogoce poslati (izcrpanih ${GOST_POSTA_POSKUSOV} poskusov)`);
      return false;
    }
    await pool.query(`UPDATE vracila SET ${m.poslano} = NOW() WHERE id = $1`, [vid]);
    console.log(`[vracila] mail kupcu (${vrsta}) poslan: narocilo ${o.public_ref}`);
    return true;
  } catch (err) { console.error(`Resend napaka (vracilo kupcu ${vrsta}, vracilo ${vid}):`, err && (err.message || String(err))); return false; }
  finally { vraciloMailVTeku.delete(kljuc); }
}

// #309 (migracija 053): vracilo, narejeno ZUNAJ Outlyja (Stripova nadzorna plosca), pride kot webhook charge.refunded; placila_stripe.js vracilo() v isti transakciji
// kot stanje narocila vpise vrstico v vracila_iz_stripa (ena na Stripovo vracilo, Martin 20. 10. 2026). Mail »vrnili smo X« kupcu natanko enkrat na vracilo, vzorec kot posljiVraciloKupcu (claim v bazi
// + mnozica v teku + mail_poslano_at po uspehu Resenda). Poslje ga webhook po COMMIT-u (brez cakanja) in pospravljalec mailov (gostPosljiNeposlane); posiljanje gre skozi
// semafor potrdil (potrdiloPosta), zato ne zasede procesa. Pogoj VRACILO_IZ_STRIPA_POGOJ: naroceno brez vrstice v `vracila` (razen `preklicano`) - nase vracilo
// (odpoved dogodka, inactive_order) kupca obvesca obdelovalec vracil; vrstica `vracila` vedno nastane PRED klicem Stripa, zato dirke z webhookom ni.
// Pogoj sme postati resnicen pozneje (npr. vrstica `preklicano`): mail se le ODLOZI (brez claima, poskus se ne porabi), pospravljalec gleda 30 dni nazaj.
const VRACILO_IZ_STRIPA_POGOJ = `NOT EXISTS (SELECT 1 FROM vracila vv WHERE vv.order_id = s.order_id AND vv.stanje <> 'preklicano')`;
// Vrstni red (I51): vracila istega naboja gredo kupcu PO VRSTI (skupaj_vrnjeno, nato cas); novejse caka, dokler starejse ni poslano ali izcrpano (poskusi = max).
// Sicer bi zakasnel mail starejsega delnega vracila kot zadnji rekel »vstopnice ostanejo veljavne«, ceprav so vrnjene. Pogoj je v claimu (velja med instancami).
const VRACILO_IZ_STRIPA_PO_VRSTI = `NOT EXISTS (SELECT 1 FROM vracila_iz_stripa sp WHERE sp.charge_id = s.charge_id AND sp.mail_poslano_at IS NULL AND sp.mail_poskusi < $2
                                        AND (sp.skupaj_vrnjeno_cents, sp.created_at, sp.vracilo_id) < (s.skupaj_vrnjeno_cents, s.created_at, s.vracilo_id))`;
const vraciloIzStripaVTeku = new Set();
// Po COMMIT-u webhooka charge.refunded: vsa neposlana vracila tega naboja (vsako Stripovo vracilo svoj mail), po vrsti.
async function posljiVracilaIzStripaNaboja(chargeId) {
  if (!resend) return;
  const r = await pool.query("SELECT vracilo_id FROM vracila_iz_stripa WHERE charge_id = $1 AND mail_poslano_at IS NULL ORDER BY skupaj_vrnjeno_cents, created_at, vracilo_id", [String(chargeId)]);
  for (const x of r.rows) if (!(await posljiVraciloIzStripa(x.vracilo_id))) break;   // po vrsti: neuspeh starejsega ustavi novejse (ponovi pospravljalec)
}
async function posljiVraciloIzStripa(vracId) {
  if (!resend) return false;
  const kljuc = String(vracId);
  if (vraciloIzStripaVTeku.has(kljuc)) return false;
  vraciloIzStripaVTeku.add(kljuc);
  try {
    if (!(await potrdiloPostaVstopi())) return false;   // polna vrsta: pospravljalec poskusi pozneje (poskus se se ni porabil)
    try { return await vraciloIzStripaPosljiEno(kljuc); }
    catch (err) { console.error(`Resend napaka (vracilo iz Stripa, ${kljuc}):`, err && (err.message || String(err))); return false; }
    finally { potrdiloPostaIzstopi(); }
  } finally { vraciloIzStripaVTeku.delete(kljuc); }
}
async function vraciloIzStripaPosljiEno(vracId) {
  const k = await pool.query(
    `UPDATE vracila_iz_stripa s SET mail_poskusi = s.mail_poskusi + 1, mail_prevzeto_at = NOW()
      WHERE s.vracilo_id = $1 AND s.mail_poslano_at IS NULL AND s.mail_poskusi < $2 AND ${VRACILO_IZ_STRIPA_POGOJ} AND ${VRACILO_IZ_STRIPA_PO_VRSTI}
        AND (s.mail_prevzeto_at IS NULL OR s.mail_prevzeto_at < NOW() - ($3::bigint[])[s.mail_poskusi + 1] * INTERVAL '1 millisecond')
      RETURNING s.order_id, s.znesek_cents, s.skupaj_vrnjeno_cents, s.valuta, s.mail_poskusi AS poskus`, [vracId, GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
  if (!k.rows.length) return false;
  const v = k.rows[0];
  const o = (await pool.query(
    `SELECT o.public_ref, o.buyer_email, o.quantity, o.currency, o.table_label, o.total_cents, e.title AS event_title, e.start_at, cl.name AS club_name, o.stripe_account_id
       FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = e.club_id WHERE o.id = $1`, [v.order_id])).rows[0];
  if (!o) return false;
  // Tik pred Resendom se enkrat: je medtem nastala vrstica `vracila` (npr. odpoved dogodka po vracilu v plosci)? Potem kupca obvesca obdelovalec vracil;
  // claim sprostimo brez porabe poskusa. (Okna med tem branjem in Resendom ni mogoce zapreti; oba maila bi bila resnicna.)
  if ((await pool.query("SELECT 1 FROM vracila vv WHERE vv.order_id = $1 AND vv.stanje <> 'preklicano' LIMIT 1", [v.order_id])).rows.length) {
    await pool.query("UPDATE vracila_iz_stripa SET mail_poskusi = GREATEST(mail_poskusi - 1, 0), mail_prevzeto_at = NULL WHERE vracilo_id = $1 AND mail_poslano_at IS NULL", [vracId]);
    return false;
  }
  if (!/^[^@\s]+@[^@\s]+$/.test(o.buyer_email || "") || /@outly\.invalid$/i.test(o.buyer_email)) {
    // izbrisan racun / anonimiziran gost: naslova ni vec. Claim zahteva poskusi < max, zato je ta vrstica (in alarm) natanko enkrat; brez e-naslova v dnevniku.
    await pool.query("UPDATE vracila_iz_stripa SET mail_poskusi = $2 WHERE vracilo_id = $1 AND mail_poslano_at IS NULL", [vracId, GOST_POSTA_POSKUSOV]);
    console.error(`[vracila] POZOR: kupec narocila ${o.public_ref} ni obvescen o vracilu iz Stripove plosce (naslov izbrisan ali neveljaven) - obvesti rocno`);
    return false;
  }
  const { besedilo, html } = vraciloMailBesedilo({ ...o, currency: v.valuta || o.currency, znesek_cents: v.znesek_cents, skupaj_vrnjeno_cents: v.skupaj_vrnjeno_cents }, "iz_stripa");
  const r = await gostResendPosli({ to: o.buyer_email, subject: `${VRACILO_MAIL.vrnjeno.zadeva}: ${o.event_title} (${o.public_ref})`.slice(0, 200), html, text: besedilo });
  if (r && r.error) {
    console.error(`Resend napaka (vracilo iz Stripa, ${o.public_ref}, poskus ${v.poskus}/${GOST_POSTA_POSKUSOV}):`, JSON.stringify(r.error));
    if (v.poskus >= GOST_POSTA_POSKUSOV) console.error(`[vracila] POZOR: obvestila o vracilu iz Stripove plosce za narocilo ${o.public_ref} NI mogoce poslati (izcrpanih ${GOST_POSTA_POSKUSOV} poskusov)`);
    return false;
  }
  await pool.query("UPDATE vracila_iz_stripa SET mail_poslano_at = NOW() WHERE vracilo_id = $1", [vracId]);
  console.log(`[vracila] mail kupcu (vracilo iz Stripove plosce) poslan: narocilo ${o.public_ref}`);
  return true;
}
// Pospravljalec: neposlani maili o vracilu iz Stripa (Resend je padel, proces ugasnjen po COMMIT-u webhooka). Najvec 20 na tek, zadnjih 30 dni.
async function vraciloIzStripaPosljiNeposlane() {
  if (!resend) return;
  const r = await pool.query(
    // na naboj samo NAJSTAREJSE neposlano (neizcrpano) vracilo; ce je v premoru, novejsa istega naboja cakajo
    `SELECT n.vracilo_id FROM (
       SELECT DISTINCT ON (s.charge_id) s.vracilo_id, s.mail_poskusi, s.mail_prevzeto_at, s.created_at FROM vracila_iz_stripa s
        WHERE s.mail_poslano_at IS NULL AND s.mail_poskusi < $1 AND s.created_at > NOW() - INTERVAL '30 days' AND ${VRACILO_IZ_STRIPA_POGOJ}
        ORDER BY s.charge_id, s.skupaj_vrnjeno_cents, s.created_at, s.vracilo_id) n
      WHERE n.mail_prevzeto_at IS NULL OR n.mail_prevzeto_at < NOW() - ($2::bigint[])[n.mail_poskusi + 1] * INTERVAL '1 millisecond'
      ORDER BY n.created_at LIMIT 20`, [GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
  for (const x of r.rows) await posljiVraciloIzStripa(x.vracilo_id);
}

// Spor (chargeback): obvestilo LASTNIKU kluba ob odprtju in ob zaprtju. Prejemniki: e-naslov racuna lastnika (clubs.owner_user_id) in kontaktni e-naslov kluba.
// Ob odprtju: vstopnice naroceno na vratih ne veljajo do odlocitve. Ob zaprtju `lost`: znesek, ki ga je Outly povrnil od kluba (transfer reversal; Martin 12. 10. 2026: izgubljen spor nosi klub;
// pogodba #97 mora to klubu nalozit), ali da avtomatska povrnitev ni uspela. Mail ob zaprtju `lost` pocaka na izid povrnitve.
// #285: obvestilo lastniku kluba o sporu SAMO za placano naroceno (paid/partially_refunded/refunded; ima vstopnice). Spor na cancelled/failed/pending naroceno (I44, N3, placilo po preklicu)
// ni terjatev do kluba (placila_stripe.js spor(): povrnitev `rocno`), zato maila ni. Isti pogoj v obdelovalcu (sweep) in pri prevzemu; alias spora podan.
const { SQL_SPOR_ZA_LASTNIKA } = require("./vracila_stripe");   // ena resnica (vracila_stripe.js); I50: spor na platformno narocilo (uradni profil Outly) lastnika ne obvesti
const SPORI_STOLPCI = { odprt: ["mail_odprt_poskusi", "mail_odprt_prevzeto_at", "mail_odprt_poslano_at", ""],
  zaprt: ["mail_zaprt_poskusi", "mail_zaprt_prevzeto_at", "mail_zaprt_poslano_at", "AND s.zaprt_at IS NOT NULL AND (s.stanje <> 'lost' OR s.povrnitev_stanje IN ('opravljeno','ni_uspelo','rocno'))"] };
const sporMailVTeku = new Set();
function denarSpora(o, T) {
  if (o.stanje !== "lost") return [T("Vstopnice tega naročila spet veljajo na vratih.", "The tickets of this order are valid at the door again."),
    T(`Za vprašanja pišite na ${POSTA_ODGOVOR}.`, `For questions write to ${POSTA_ODGOVOR}.`)];
  const v = [T("Vstopnice tega naročila ostanejo neveljavne.", "The tickets of this order stay invalid.")];
  if (o.povrnitev_stanje === "opravljeno") {
    v.push(T(`Izgubljen spor nosi klub: z vašega Stripe računa smo povrnili ${znesek(o.povrnitev_cents, o.valuta || "EUR", "sl")} (znesek spora brez provizije Outly in Stripova pristojbina spora ${znesek(o.pristojbina_spora_cents, o.valuta || "EUR", "sl")}).`,
      `The club bears a lost dispute: we recovered ${znesek(o.povrnitev_cents, o.valuta || "EUR", "en")} from your Stripe account (the disputed amount net of Outly's fee, plus Stripe's dispute fee of ${znesek(o.pristojbina_spora_cents, o.valuta || "EUR", "en")}).`));
  } else {
    v.push(T(`Izgubljen spor nosi klub. Samodejna povrnitev ni uspela; Outly vas bo kontaktiral. Vprašanja: ${POSTA_ODGOVOR}.`,
      `The club bears a lost dispute. The automatic recovery did not succeed; Outly will contact you. Questions: ${POSTA_ODGOVOR}.`));
  }
  return v;
}
function sporMailBesedilo(o, vrsta) {
  return izrisiDvojezicno((jez) => {
    const T = (sl, en) => (jez === "sl" ? sl : en);
    const zaprt = vrsta === "zaprt";
    const izid = o.stanje === "won" ? T("Spor je zaključen v vašo korist.", "The dispute was decided in your favour.")
      : o.stanje === "lost" ? T("Spor je zaključen v korist imetnika kartice (izgubljen).", "The dispute was decided in the cardholder's favour (lost).")
      : T(`Stanje spora: ${o.stanje}.`, `Dispute status: ${o.stanje}.`);
    return {
      naslovBesedila: zaprt ? T(`Spor zaključen - naročilo ${o.public_ref}`, `Dispute closed - order ${o.public_ref}`) : T(`Spor zaradi plačila - naročilo ${o.public_ref}`, `Payment dispute - order ${o.public_ref}`),
      naslovHtml: zaprt ? T("Spor zaključen", "Dispute closed") : T("Spor zaradi plačila", "Payment dispute"),
      razdelki: [
        { naslov: T("Kaj se je zgodilo", "What happened"), vrstice: zaprt ? [izid]
          : String(o.stanje).startsWith("warning_") ? [T("Banka imetnika kartice je odprla poizvedbo o plačilu (še ni spor/chargeback). Vstopnice ostanejo veljavne.", "The cardholder's bank opened an inquiry about a payment (not yet a dispute/chargeback). The tickets stay valid.")]
          : [T("Imetnik kartice je pri svoji banki izpodbijal plačilo (spor, chargeback). Znesek spora je do odločitve banke začasno odtegnjen.", "A cardholder disputed a payment with their bank (a chargeback). The disputed amount is withheld until the bank decides.")] },
        { naslov: T("Naročilo", "Order"), vrstice: [T(`Naročilo ${o.public_ref}, dogodek »${o.event_title}«. Znesek spora: ${znesek(o.znesek_cents, o.valuta || "EUR", "sl")}. Razlog (po Stripu): ${o.razlog || "?"}.`,
          `Order ${o.public_ref}, event "${o.event_title}". Disputed amount: ${znesek(o.znesek_cents, o.valuta || "EUR", "en")}. Reason (per Stripe): ${o.razlog || "?"}.`)] },
        { naslov: T("Naslednji koraki", "Next steps"), vrstice: zaprt ? denarSpora(o, T) : String(o.stanje).startsWith("warning_") ? [T(`Odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR}, če imate podatke, ki bi pomagali (npr. dokaz o obisku).`, `Reply to this email or write to ${POSTA_ODGOVOR} if you have information that could help (for example proof of attendance).`)] : [T(`Vstopnice tega naročila na vratih do odločitve ne veljajo. Če imate podatke, ki bi pomagali (npr. dokaz o obisku), odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR}.`,
          `The tickets of this order are not valid at the door until the dispute is decided. If you have information that could help (for example proof of attendance), reply to this email or write to ${POSTA_ODGOVOR}.`)] },
      ],
    };
  });
}
async function posljiSporMail(did, vrsta) {
  if (!resend) return false;
  const [cPoskusi, cPrevzeto, cPoslano, dodatek] = SPORI_STOLPCI[vrsta];
  const kljuc = `${did}:${vrsta}`;
  if (sporMailVTeku.has(kljuc)) return false;
  sporMailVTeku.add(kljuc);
  try {
    const k = await pool.query(
      `UPDATE spori s SET ${cPoskusi} = s.${cPoskusi} + 1, ${cPrevzeto} = NOW()
        WHERE s.id = $1 AND s.${cPoslano} IS NULL AND s.${cPoskusi} < $2 ${dodatek} AND (s.order_id IS NULL OR ${SQL_SPOR_ZA_LASTNIKA("s")})
          AND (s.${cPrevzeto} IS NULL OR s.${cPrevzeto} < NOW() - ($3::bigint[])[s.${cPoskusi} + 1] * INTERVAL '1 millisecond')
        RETURNING s.order_id, s.stanje, s.razlog, s.znesek_cents, s.valuta, s.povrnitev_stanje, s.povrnitev_cents, s.pristojbina_spora_cents, s.${cPoskusi} AS poskus`, [did, GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
    if (!k.rows.length) return false;
    const sp = k.rows[0];
    if (sp.order_id === null) {   // spora ni mogoce povezati z narocilom: lastnika ne poznamo, alarm je ze v dnevniku (POZOR ob zapisu spora)
      await pool.query(`UPDATE spori SET ${cPoskusi} = $2 WHERE id = $1 AND ${cPoslano} IS NULL AND order_id IS NULL`, [did, GOST_POSTA_POSKUSOV]);   // order_id IS NULL: ne povozi ponastavitve iz zakljuci() (spor je medtem dobil narocilo)
      return false;
    }
    const r0 = await pool.query(
      `SELECT o.public_ref, e.title AS event_title, cl.contact_email, u.email AS owner_email
         FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = e.club_id LEFT JOIN users u ON u.id = cl.owner_user_id WHERE o.id = $1`, [sp.order_id]);
    const o = r0.rows[0];
    const naslovi = o ? [...new Set([o.owner_email, o.contact_email].map((x) => String(x || "").trim().toLowerCase()).filter((x) => /^[^@\s]+@[^@\s]+$/.test(x) && !/@outly\.invalid$/.test(x)))] : [];
    if (!naslovi.length) {
      await pool.query(`UPDATE spori SET ${cPoskusi} = $2 WHERE id = $1 AND ${cPoslano} IS NULL`, [did, GOST_POSTA_POSKUSOV]);
      console.error(`[spori] POZOR: spor ${did}: lastnik kluba nima e-naslova, obvestila ni mogoce poslati`);
      return false;
    }
    const { besedilo, html } = sporMailBesedilo({ ...sp, public_ref: o.public_ref, event_title: o.event_title }, vrsta);
    const r = await gostResendPosli({ to: naslovi, subject: `${vrsta === "zaprt" ? "Spor zaključen / Dispute closed" : "Spor zaradi plačila / Payment dispute"}: ${o.public_ref}`.slice(0, 200), html, text: besedilo });
    if (r && r.error) {
      console.error(`Resend napaka (spor ${did}, ${vrsta}, poskus ${sp.poskus}/${GOST_POSTA_POSKUSOV}):`, JSON.stringify(r.error));
      if (sp.poskus >= GOST_POSTA_POSKUSOV) console.error(`[spori] POZOR: obvestila lastniku kluba o sporu ${did} NI mogoce poslati (izcrpanih ${GOST_POSTA_POSKUSOV} poskusov)`);
      return false;
    }
    await pool.query(`UPDATE spori SET ${cPoslano} = NOW() WHERE id = $1`, [did]);
    console.log(`[spori] mail lastniku kluba poslan: spor ${did} (${vrsta})`);
    return true;
  } catch (err) { console.error(`Resend napaka (spor ${did}):`, err && (err.message || String(err))); return false; }
  finally { sporMailVTeku.delete(kljuc); }
}
// Po COMMIT-u webhooka (placila_stripe.js naSporu): odprt spor takoj; zaprt, ce je zaprt. Ostalo ponovi obdelovalec.
async function posljiSporLastniku(did) {
  await posljiSporMail(did, "odprt");
  await posljiSporMail(did, "zaprt");
}
// Obdelovalec vracil po vsakem teku: neposlana obvestila kupcem (najvec 20 na tek, razmik za Resend) in lastnikom klubov.
async function vracilaObvestilaNeposlana() {
  if (!resend) return;
  const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms));
  for (const vrsta of ["odpoved", "vrnjeno", "ni_izvedeno"]) {   // `ni_izvedeno` za `odpoved`: v istem teku sele po poslanem mailu odpoved
    const m = VRACILO_MAIL[vrsta];
    const r = await pool.query(
      `SELECT v.id FROM vracila v WHERE ${m.pogoj} AND v.${m.poslano} IS NULL AND v.${m.poskusi} < $1
          AND (v.${m.prevzeto} IS NULL OR v.${m.prevzeto} < NOW() - ($2::bigint[])[v.${m.poskusi} + 1] * INTERVAL '1 millisecond')
        ORDER BY v.id LIMIT $3`, [GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI, VRACILA_MAIL_PAKET]);
    for (const v of r.rows) { if (await posljiVraciloKupcu(v.id, vrsta) && VRACILA_MAIL_RAZMAK_MS) await pocakaj(VRACILA_MAIL_RAZMAK_MS); }
  }
  const sp = await pool.query(
    `SELECT id FROM spori WHERE order_id IS NOT NULL AND ${SQL_SPOR_ZA_LASTNIKA("spori")} AND ((mail_odprt_poslano_at IS NULL AND mail_odprt_poskusi < $1)
        OR (zaprt_at IS NOT NULL AND mail_zaprt_poslano_at IS NULL AND mail_zaprt_poskusi < $1)) AND ustvarjen_at > NOW() - INTERVAL '60 days' ORDER BY ustvarjen_at LIMIT 10`, [GOST_POSTA_POSKUSOV]);
  for (const x of sp.rows) await posljiSporLastniku(x.id);
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
    // Issue #264: zgornji DELETE vidi samo zetone, potrjene pred zacetkom ukaza. Kovanje (gostKujZeton) e-naslov in user_id prebere brez zaklepa
    // (FK vzame le KEY SHARE, ki se z UPDATE ne tepe): ce je bralo tik pred anonimizacijo/prevzemom in se potrdilo po njem, zeton ostane ob
    // narocilu, ki ni vec gostujoce (neuporaben, poizvedba zahteva e-naslov in user_id NULL, a bi lezal do konca dogodka + 30 dni). Pobere ga naslednji tek.
    const sir = await pool.query(
      `DELETE FROM gost_zetoni z USING orders o WHERE o.id = z.order_id AND (o.guest_email IS NULL OR o.user_id IS NOT NULL)`);
    if (sir.rowCount > 0) console.log(`[gost] pospravljenih zetonov narocil, ki niso vec gostujoca: ${sir.rowCount}`);
    // Vstopnice, poslane gostu (034): zetoni potecejo in e-naslov imetnika se izbrise konec dogodka + 30 dni (GOST_ZETON_DNI; pravna presoja 1.4).
    // holder_is_guest OSTANE (vstopnica ne sme spet postati kupceva); zapis prenosa dobi neosebno oznako.
    // Anonimizacija e-naslova in brisanje zetonov sta ENA transakcija (issue #240). Prej sta bila dva loceni ukaza (najprej DELETE zetonov, nato UPDATE
    // e-naslova): ce je rok hrambe potekel med njima (dogodek premaknjen / meja casa), je DELETE se videl veljaven dogodek, UPDATE pa potekel -> e-naslov
    // izbrisan, zeton ostal do naslednjega teka (verjetni vzrok nestabilnega testa v razdelku 8). Poleg tega mail, ki je vstopnico PREVZEL (e-naslov se je
    // takrat se bral), kuje zeton (gostKujZetonVstopnice) pred pripravo priloge, torej po prevzemu, a lahko po pospravljalcu. UPDATE tickets zato pocaka
    // na zaklep vrstice, ki ga drzi kovanje (FOR UPDATE), DELETE zetonov je nov ukaz (nov posnetek) in zeton vidi. Zunanji opazovalec nikoli ne vidi
    // »e-naslov izbrisan, zeton obstaja«; poizvedba po zetonu (gostVstopnicaPoZetonu) zahteva e-naslov se vpisan.
    const konec = `COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') + INTERVAL '${GOST_ZETON_DNI} days' < NOW()`;
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      const at = await c.query(
        `WITH k AS (SELECT t.id FROM tickets t JOIN events e ON e.id = t.event_id WHERE t.holder_guest_email IS NOT NULL AND ${konec} LIMIT 1000),
              u AS (UPDATE tickets t SET holder_guest_email = NULL FROM k WHERE t.id = k.id RETURNING t.id),
              p AS (UPDATE ticket_transfers x SET to_email = 'izbrisan-' || x.id || '@outly.invalid', to_email_norm = NULL
                     WHERE x.to_guest AND x.to_user_id IS NULL AND x.ticket_id IN (SELECT id FROM u) RETURNING 1)
         SELECT (SELECT COUNT(*)::int FROM u) AS n`);
      await c.query(`DELETE FROM gost_zetoni_vstopnic z USING tickets t, events e WHERE t.id = z.ticket_id AND e.id = t.event_id AND ${konec}`);
      await c.query("COMMIT");
      if (at.rows[0].n > 0) console.log(`[gost] anonimiziranih prenesenih gostujocih vstopnic: ${at.rows[0].n}`);
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
    finally { c.release(); }
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

// naslov = e-naslov imetnika, ki ga je mail PREVZEL: ce se je vstopnica medtem prevzela v racun in prenesla drugemu gostu (drug e-naslov), stari mail
// zetona za novega imetnika ne sme skovati (in ga poslati staremu naslovu).
async function gostKujZetonVstopnice(db, tid, naslov) {
  const zeton = crypto.randomBytes(32).toString("base64url");
  // Po roku hrambe (konec dogodka + GOST_ZETON_DNI) ali po anonimizaciji e-naslova zetona NE kujemo (issue #240: mail, ki je vstopnico prevzel pred iztekom
  // roka, bi sicer skoval zeton PO pospravljalcu). FOR UPDATE OF t: pospravljalec in admin izbris (UPDATE tickets, nato DELETE zetonov v isti transakciji)
  // pocakata, da se zeton vstavi, in ga nato izbrisejo; kdor pride za njim, vidi e-naslov NULL (ponovno preverjanje po cakanju) in zetona ne dobi.
  const r = await db.query(
    `INSERT INTO gost_zetoni_vstopnic (token_hash, ticket_id)
       SELECT $1, t.id FROM tickets t JOIN events e ON e.id = t.event_id
        WHERE t.id = $2 AND t.holder_is_guest AND t.holder_guest_email = $3
          AND COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') + INTERVAL '${GOST_ZETON_DNI} days' > NOW()
          FOR UPDATE OF t`, [gostZetonHash(zeton), tid, naslov]);
  if (!r.rowCount) return null;   // vstopnica ni (vec) gostujoca (prevzeta v racun), imetnik/e-naslov se je spremenil ali izbrisal, ali rok hrambe je potekel: zetona ni
  await db.query(
    `DELETE FROM gost_zetoni_vstopnic WHERE ticket_id = $1
       AND token_hash NOT IN (SELECT token_hash FROM gost_zetoni_vstopnic WHERE ticket_id = $1 ORDER BY created_at DESC LIMIT ${GOST_ZETONOV_NA_NAROCILO})`, [tid]);
  return zeton;
}
// id vstopnice za zeton ali null (napacen, potekel, izbrisan (e-naslov NULL), prevzet v racun, ponovno prenesen: vse enako, brez razlike). Indeksirano (PK) in poceni.
async function gostVstopnicaPoZetonu(db, zeton) {
  if (typeof zeton !== "string" || !GOST_ZETON_VZOREC.test(zeton)) return null;
  const r = await db.query(
    `SELECT t.id FROM gost_zetoni_vstopnic z JOIN tickets t ON t.id = z.ticket_id JOIN events e ON e.id = t.event_id
      WHERE z.token_hash = $1 AND t.holder_is_guest AND t.holder_guest_email IS NOT NULL
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
      "address", "city", "logo_url", "venue_club_id", "venue_club_name", "venue_club_logo_url", "venue_name", "venue_address", "venue_city", "venue_lat", "venue_lng",
      "is_vip", "table_label", "table_seats", "package_name", "package_description", "public_ref", "transferred", "holder_username", "is_guest_holder", "payment_disputed"]) bel[k] = t[k];
    return res.json({
      ticket: { ...bel, qr: qrVstopnice(t), transferable: false, from_username: pos, buyer_username: pos },   // gost vstopnice ne more naprej (brez racuna)
      event: { id: t.event_id, title: t.event_title, start_at: t.start_at, end_at: t.end_at, poster_url: t.poster_url, min_age: t.min_age,
               club_id: t.club_id, club_name: t.club_name, address: t.address, city: t.city, logo_url: t.logo_url, ...prizoriscePolja(t) },
    });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- mail prejemniku ---
// Vsebina po pravni presoji (outly-hq pravno/2026-10-05-prenos-brez-racuna.md, razdelki 1.3, 3, 5): obvestilo po GDPR 14 v CELOTI v mailu (politika prenosa brez racuna
// ne opisuje), pravica do ugovora (21(4)) v LOCENEM odstavku, varnostno besedilo, en nevtralen stavek o prevzemu v racun (ne trzenje, ZEKom-2 226), brez oglasov.
// Pošiljatelj = uporabniško ime (nikoli e-naslov). Brez sledenja (to nastavlja Resend na domeni). E-naslova prejemnika ni v PDF.
function prenosPotrdilo(x, povezava, kode) {
  return izrisiDvojezicno((jez) => {
    const T = (sl, en) => (jez === "sl" ? sl : en);
    const klubKontakt = [x.club_phone, x.club_email].filter(Boolean).join(", ");
    const meja = starostZaPaket(x.min_age, x.package_id !== null && x.package_id !== undefined);
    const pretvorbaMeje = meja > x.min_age;
    const starost = meja > 0
      ? T(`Starostna meja: ${meja}+${pretvorbaMeje ? " (miza s paketom pijače)" : ""}. Pri vhodu pokažite veljaven osebni dokument s fotografijo; če ste mlajši od ${meja} let, vam bo klub zavrnil vstop.`,
          `Age limit: ${meja}+${pretvorbaMeje ? " (table with a drinks package)" : ""}. Show a valid photo ID at the door; if you are under ${meja}, the club will refuse entry.`)
      : T("Brez starostne omejitve.", "No age limit.");
    const vrsta = x.table_label
      ? T(`VIP miza ${x.table_label}${x.package_name ? `, paket: ${x.package_name}` : ""}`, `VIP table ${x.table_label}${x.package_name ? `, package: ${x.package_name}` : ""}`)
      : T("Standardna vstopnica", "Standard ticket");
    const posiljatelj = x.from_username || T("Uporabnik Outly", "An Outly user");
    const kdoSl = x.from_username ? `uporabnik Outly ${x.from_username}` : "uporabnik Outly";   // brez spola; ob manjkajocem imenu ne podvajamo »Outly«
    const razdelki = [
      { naslov: T("To je vaša vstopnica", "This is your ticket"), vrstice: [T(QR_STAVEK_SL, QR_STAVEK)], krepko: true },
      { naslov: T("Dogodek", "Event"), vrstice: [x.event_title, ljDatum(x.start_at, jez), prizoriscePodatki(x),
          T(`Organizator: ${x.club_name}${klubKontakt ? ` (${klubKontakt})` : ""}. Glede samega dogodka se obrnite na organizatorja.`,
            `Organiser: ${x.club_name}${klubKontakt ? ` (${klubKontakt})` : ""}. Contact the organiser about the event itself.`), starost] },
      { naslov: T("Vaša vstopnica", "Your ticket"), vrstice: [vrsta, T(`Kodo QR pokažite pri vhodu (je tudi v priloženem PDF, outly-ticket.pdf): ${povezava}`, `Show this QR code at the door (it is also in the attached PDF, outly-ticket.pdf): ${povezava}`)],
        slika: kode.map((k) => ({ cid: k.cid, oznaka: oznakaKode(k, jez), alt: T("Koda QR vstopnice", "Ticket QR code") })) },
      { naslov: T("Pravila vstopnice", "Ticket rules"), vrstice: T(
          ["En vstop na kodo.", "Organizator vam lahko zavrne vstop na podlagi hišnega reda ali zakona.", "Preprodaja vstopnice ni dovoljena.",
           "Če je dogodek odpovedan, se vračilo izplača osebi, ki je vstopnico kupila, ne vam.", "Če z istim e-naslovom ustvarite račun Outly, se bo vstopnica pojavila tam."],
          ["One entry per code.", "The organiser may refuse entry under its house rules or the law.", "Reselling the ticket is not allowed.",
           "If the event is cancelled, a refund goes to the person who bought the ticket, not to you.", "If you create an Outly account with this email, the ticket will appear there."]) },
      { naslov: T("Vstopnice niste pričakovali?", "Not for you?"), vrstice: [T("Če te vstopnice niste pričakovali, odgovorite na to sporočilo in vaš e-naslov bomo izbrisali.",
          "If you were not expecting this ticket, reply to this email and we will delete your email address.")] },
      { naslov: T("O vašem e-naslovu (GDPR, 14. člen)", "About your email address (GDPR, Article 14)"), vrstice: T([
          `Kdo smo: ${POSREDNIK_VRSTICA}.`,
          `Zakaj: vaš e-naslov uporabljamo samo za dostavo te vstopnice in za omogočanje vstopa. Pravna podlaga: zakoniti interes (GDPR, člen 6(1)(f)): ${kdoSl} vam želi predati to vstopnico.`,
          `Od kod podatek: vnesel ga je ${kdoSl}.`,
          `Podatki: vaš e-naslov, vstopnica in dogodek, potrditev pošiljatelja, da izpolnjujete starostno mejo (če obstaja), ter čas skeniranja vstopnice ob vstopu.`,
          `Prejemniki: Resend (dostava e-pošte). Organizator (${x.club_name}) vidi samo, da je bila vstopnica predana gostu, ne pa vašega e-naslova.`,
          `Prenos izven EGP: naš ponudnik e-pošte ima sedež v Združenih državah Amerike; prenos temelji na standardnih pogodbenih klavzulah EU ali na sklepu o ustreznosti, kot je opisano v naši politiki zasebnosti.`,
          `Hramba: vaš e-naslov izbrišemo 30 dni po koncu dogodka, razen če z njim ustvarite račun Outly.`,
          `Vaše pravice: dostop, popravek, izbris, omejitev obdelave in pritožba pri Informacijskem pooblaščencu Republike Slovenije (www.ip-rs.si). Politika zasebnosti: https://outly.si/privacy` ], [
          `Who we are: ${POSREDNIK_VRSTICA}.`,
          `Why: we use your email address only to deliver this ticket and to allow entry. Legal basis: legitimate interest (GDPR Article 6(1)(f)): ${posiljatelj} wanted to pass this ticket on to you.`,
          `Where we got it: ${posiljatelj}, an Outly user, entered your email address.`,
          `Data: your email address, the ticket and event, the sender's confirmation that you meet the age limit (if there is one), and the time the ticket is scanned at entry.`,
          `Recipients: Resend (email delivery). The organiser (${x.club_name}) only sees that the ticket was passed on to a guest, not your email address.`,
          `Transfer outside the EEA: our email provider is based in the United States; the transfer relies on the EU standard contractual clauses or an adequacy decision, as described in our privacy policy.`,
          `Retention: we delete your email address 30 days after the event ends, unless you create an Outly account with it.`,
          `Your rights: access, rectification, erasure, restriction, and a complaint to the Information Commissioner of Slovenia (www.ip-rs.si). Privacy policy: https://outly.si/privacy` ]) },
      { naslov: T("Pravica do ugovora", "Right to object"), vrstice: [T("Ne želite, da obdelujemo vaš e-naslov? Pravico do ugovora imate kadar koli: odgovorite na to sporočilo in vaš naslov bomo izbrisali.",
          "Don't want us to process your email address? You have the right to object at any time: reply to this email and we will delete your address.")] },
      { naslov: T("Vprašanja", "Questions"), vrstice: [T(`Odgovorite na to sporočilo ali pišite na ${POSTA_ODGOVOR}.`, `Reply to this email or write to ${POSTA_ODGOVOR}.`)] },
    ];
    return { naslovBesedila: T(`${posiljatelj} vam je poslal(-a) vstopnico za ${x.event_title}`, `${posiljatelj} sent you a ticket for ${x.event_title}`),
      naslovHtml: T(`${posiljatelj} vam je poslal(-a) vstopnico`, `${posiljatelj} sent you a ticket`), razdelki };
  }, povezava);
}

// Meje maila (zloraba: mail na tuj naslov) so v transakciji prenosa (POST /tickets/:id/transfer): GOST_PRENOS_NA_DAN na posiljatelja, GOST_PRENOS_NA_NASLOV na naslov.
async function posljiPrenosGostu(tid) {
  if (!resend) return false;
  const kljuc = String(tid);   // kot pri posljiGostuVstopnice: kljuc je vedno niz
  if (prenosVTeku.has(kljuc)) return false;   // isti vzorec kot posljiGostuVstopnice (#201)
  prenosVTeku.add(kljuc);
  try {
    if (!(await gostPostaVstopi())) return false;
    try { return await prenosPosljiEnoPosto(tid); }
    catch (err) { console.error(`Resend napaka (prenos gostu, vstopnica ${tid}):`, err && (err.message || String(err))); return false; }
    finally { gostPostaIzstopi(); }
  } finally { prenosVTeku.delete(kljuc); }
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
            cl.contact_phone AS club_phone, cl.contact_email AS club_email, o.package_id, o.table_label, o.package_name, ${PRIZORISCE_MAIL_STOLPCI},
            (SELECT u.username FROM ticket_transfers tt JOIN users u ON u.id = tt.from_user_id WHERE tt.ticket_id = t.id AND tt.to_guest ORDER BY tt.id DESC LIMIT 1) AS from_username
       FROM tickets t JOIN orders o ON o.id = t.order_id JOIN events e ON e.id = t.event_id JOIN clubs cl ON cl.id = e.club_id ${PRIZORISCE_JOIN} WHERE t.id = $1`, [tid]);
  if (!ev.rows.length) return false;
  const x = ev.rows[0];
  const zeton = await gostKujZetonVstopnice(pool, tid, t.holder_guest_email);
  if (!zeton) return false;   // medtem prevzeto v racun / prenesenemu drugam / izbrisano / rok hrambe potekel
  const kode = [{ cid: "ticket-qr-1", oznaka: "", koda: qrVstopnice(t) }];
  const meja = starostZaPaket(x.min_age, x.package_id !== null);
  const vrsta = x.table_label ? `VIP table ${x.table_label}${x.package_name ? ` - ${x.package_name}` : ""}` : "Standard ticket";
  const povezava = gostVstopnicaPovezava(zeton);
  const { besedilo, html } = prenosPotrdilo(x, povezava, kode);
  const priloge = await prilogeVstopnic({ ...x, starostPdf: meja > 0 ? `Age ${meja}+ - bring a valid photo ID` : "" }, kode.map(c => ({ ...c, vrsta })), "outly-ticket.pdf");
  const r = await gostResendPosli({ to: t.holder_guest_email, subject: `${x.from_username || "An Outly user"} vam je poslal(-a) vstopnico / sent you a ticket: ${x.event_title}`.slice(0, 200), html, text: besedilo, attachments: priloge });
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
    // UPDATE e-naslova, nato DELETE zetonov v isti transakciji kot pri pospravljalcu (#240): DELETE v CTE istega ukaza bi videl posnetek z zacetka ukaza in
    // zeton, ki ga ravnokar kuje mail v teku (drzi zaklep vrstice), bi ostal veljaven.
    const c = await pool.connect();
    let r;
    try {
      await c.query("BEGIN");
      const t = await c.query("UPDATE tickets SET holder_guest_email = NULL WHERE holder_is_guest AND holder_guest_email = $1 RETURNING id", [email]);
      if (t.rows.length) await c.query("DELETE FROM gost_zetoni_vstopnic WHERE ticket_id = ANY($1::int[])", [t.rows.map(x => x.id)]);
      const x = await c.query(
        `UPDATE ticket_transfers SET to_email = 'izbrisan-' || id || '@outly.invalid', to_email_norm = NULL
          WHERE to_guest AND to_user_id IS NULL AND to_email = $1`, [email]);
      await c.query("COMMIT");
      r = { rows: [{ tickets: t.rows.length, transfers: x.rowCount }] };
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
    finally { c.release(); }
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
         LEFT JOIN orders o ON o.club_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_PRAVO_NAROCILO}
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
       LEFT JOIN orders o ON o.club_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_PRAVO_NAROCILO}
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
      // Ena poizvedba za pravi (summary) IN testni (test_summary, #236) promet: samo 5 vzporednih poizvedb na ogled plosce (pool ima 10 povezav).
      pool.query(
        `SELECT COALESCE(SUM(o.total_cents) FILTER (WHERE ${SQL_PRAVO_NAROCILO}),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${SQL_PRAVO_NAROCILO}),0)::int AS fee_cents,
                COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents) FILTER (WHERE ${SQL_PRAVO_NAROCILO}),0)::int AS net_cents,
                -- tickets_sold = samo navadne vstopnice (narocila brez mize); gross_cents vkljucuje mize (migracija 025).
                COALESCE(SUM(o.quantity) FILTER (WHERE ${SQL_PRAVO_NAROCILO} AND o.table_id IS NULL),0)::int AS tickets_sold,
                COUNT(*) FILTER (WHERE ${SQL_PRAVO_NAROCILO})::int AS orders,
                COUNT(DISTINCT COALESCE(o.user_id::text, lower(o.guest_email))) FILTER (WHERE ${SQL_PRAVO_NAROCILO})::int AS buyers,
                COALESCE(SUM(o.total_cents) FILTER (WHERE ${SQL_PRAVO_NAROCILO} AND o.created_at > NOW() - INTERVAL '7 days'),0)::int AS gross_7d_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE ${SQL_PRAVO_NAROCILO} AND o.created_at > NOW() - INTERVAL '7 days' AND o.table_id IS NULL),0)::int AS tickets_7d,
                COUNT(*) FILTER (WHERE ${SQL_PRAVO_NAROCILO} AND o.table_id IS NOT NULL)::int AS tables_sold,
                COALESCE(SUM(o.total_cents) FILTER (WHERE ${SQL_PRAVO_NAROCILO} AND o.table_id IS NOT NULL),0)::int AS tables_gross_cents,
                -- test_summary (DODANO polje): ves testni promet TEGA kluba od zacetka (ni pravi denar); tickets_sold brez miz kot zgoraj
                COUNT(*) FILTER (WHERE ${SQL_TESTNO_NAROCILO})::int AS test_orders,
                COALESCE(SUM(o.total_cents) FILTER (WHERE ${SQL_TESTNO_NAROCILO}),0)::int AS test_gross_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE ${SQL_TESTNO_NAROCILO} AND o.table_id IS NULL),0)::int AS test_tickets_sold
         FROM orders o WHERE o.club_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL`, [klub]),   // guest lista (035, I24) ni prodaja: ne v bruto, tickets_sold, stevilo narocil; testno narocilo (#236, I39) ni v summary
      pool.query(
        `SELECT e.id, e.title, e.start_at, e.poster_url, e.status, e.ticket_price_cents, e.capacity, e.sold_count,
                -- #236 (I39): samo PRAVI promet. Pogoj je v FILTER (ne v ON): dogodek brez pravega prometa ostane v seznamu z nicelami.
                COALESCE(SUM(o.total_cents) FILTER (WHERE o.status IN ('paid','partially_refunded') AND ${SQL_PRAVO_NAROCILO}),0)::int AS gross_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.status IN ('paid','partially_refunded') AND ${SQL_PRAVO_NAROCILO} AND o.table_id IS NULL),0)::int AS tickets_sold,
                COUNT(o.id) FILTER (WHERE o.status IN ('paid','partially_refunded') AND ${SQL_PRAVO_NAROCILO} AND o.table_id IS NOT NULL)::int AS tables_sold,
                COALESCE(SUM(o.total_cents) FILTER (WHERE o.status IN ('paid','partially_refunded') AND ${SQL_PRAVO_NAROCILO} AND o.table_id IS NOT NULL),0)::int AS tables_gross_cents,
                (SELECT COUNT(*)::int FROM tickets t WHERE t.event_id = e.id AND t.status = 'used') AS checked_in,
                -- Koliko oseb je oznacilo "I'm in" na tem dogodku (migracija 020). DODANO polje.
                (SELECT COUNT(*)::int FROM event_interest ei WHERE ei.event_id = e.id) AS interested_count
         FROM events e LEFT JOIN orders o ON o.event_id = e.id AND o.guest_list_id IS NULL
         WHERE e.club_id = $1 GROUP BY e.id ORDER BY e.start_at DESC LIMIT 100`, [klub]),
      pool.query(
        // test_payment (#236, DODANO polje): testno naročilo (lažni način ALI Stripe sandbox, SQL_TESTNO_NAROCILO). is_test ostane v starem pomenu (lažni način brez plačila).
        `SELECT ${STOLPCI_NAROCILA}, ${SQL_TESTNO_NAROCILO} AS test_payment, e.title AS event_title, COALESCE(u.username, ${IME_GOSTA}) AS buyer_username
         FROM orders o JOIN events e ON e.id = o.event_id LEFT JOIN users u ON u.id = o.user_id
         WHERE o.club_id = $1 AND o.guest_list_id IS NULL ORDER BY o.created_at DESC LIMIT 30`, [klub]),
      // Zadnjih 14 dni po dnevih (tudi dnevi brez prodaje), za graf v nadzorni plosci.
      pool.query(
        `SELECT to_char(d.dan, 'YYYY-MM-DD') AS day,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets
         FROM generate_series((CURRENT_DATE - INTERVAL '13 days')::date, CURRENT_DATE, '1 day') AS d(dan)
         LEFT JOIN orders o ON o.club_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND ${SQL_PRAVO_NAROCILO}
              AND o.created_at >= d.dan AND o.created_at < d.dan + INTERVAL '1 day'
         GROUP BY d.dan ORDER BY d.dan`, [klub]),
      // Novo, samo ce je ?range= navedеn — DODANO polje, star odjemalec (brez range) ga ne dobi.
      range ? serijaProdaje(klub, range) : Promise.resolve(null),
    ]);
    // Provizija TEGA kluba (031), ce jo je admin nastavil; sicer privzeta. Lastnik vidi svojo pogodbeno provizijo.
    const kp = (await pool.query(`SELECT commission_bps, is_demo, ${sqlPlacilaPripravljena()} AS stripe_pripravljen, is_official, ${STOLPCI_PRODAJALCA}, contact_phone, contact_email FROM clubs WHERE id=$1`, [klub])).rows[0];
    const nacinKluba = placilaStripe.nacinPlacilaZ(!!(kp && kp.stripe_pripravljen));
    const { test_orders, test_gross_cents, test_tickets_sold, ...summary } = povzetek.rows[0];
    const odgovor = {
      mode: testniNacinPlacil() ? "test" : "live",
      // Nacin placila TEGA kluba (#149/#191): "test" | "stripe" | "unavailable"; `mode` zgoraj je globalen (samo ali je sistem v testnem nacinu). DODANO polje.
      // #220: ob sk_live_ in nepopolnih podatkih prodajalca (I34) "unavailable" (placljiv nakup bi bil 409); znesek ni znan, zato se predpostavi placljivo.
      payment_mode: kp && kp.is_demo ? "unavailable" : javniNacinProdajalca(nacinKluba, kp || {}, 1, false),
      // Zakaj je "unavailable" (DODANO polje, lastnik in manager): "demo_club" (050) | "seller_incomplete" | "stripe_not_ready" | "payments_not_configured" | null (payment_mode ni "unavailable").
      payment_unavailable_reason: kp && kp.is_demo ? "demo_club" : razlogNerazpolozljivosti(nacinKluba, kp || {}, 1, false),
      // I50: `fee_percent` = provizija za NOVE prodaje kluba DANES (uradni profil Outly = platforma -> 0), NE povprecje preteklih naroceil: klub, ki mu admin vklopi is_official,
      // ima stara `acct_` naroceila po 10 %, ta pa so pravilno v summary.fee_cents / application_fee_cents (zneski odlocajo po oznaki naroclila, ne po tem polju).
      fee_percent: kp && kp.is_official === true ? 0 : (kp && kp.commission_bps !== null ? kp.commission_bps / 100 : PROVIZIJA_ODSTOTEK),
      summary,   // #236: samo pravi promet (testni je v test_summary)
      test_summary: { orders: test_orders, gross_cents: test_gross_cents, tickets_sold: test_tickets_sold },
      events: poDogodkih.rows,
      recent_orders: zadnja.rows,
      sales_by_day: poDnevih.rows,
    };
    if (range) odgovor.series = serija;
    return res.json(odgovor);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /business/events/:id/tickets — vstopnice dogodka (za vrata: kdo je prišel).
// BREZ poizvedbenih parametrov: golo polje, najvec 1000 vstopnic po id (oblika, ki jo poznata iOS in splet; pri vec kot 1000 je rez tih).
// Z `limit`, `offset` ali `q` (#277 N1): ovojnica { tickets, counts, total, limit, offset, has_more, next_offset } - glej ARCHITECTURE »Seznam vstopnic«.
//   limit 0..1000 (privzeto 200; 0 = samo stevci), offset >= 0, q = podniz (1..64 znakov, brez razlike velikosti) po tem, kar vloga SME videti:
//   public_ref, serial, uporabnisko ime kupca in imetnika; lastnik in manager se po e-naslovu kupca/imetnika (vratar nikoli, I21; vstopnice guest liste
//   nikoli: njihovih e-naslovov odgovor ne vrne). `counts` stejejo VSE vstopnice dogodka, neodvisno od q/limit/offset.
const VSTOPNICE_LIMIT_NAJVEC = 1000;
const VSTOPNICE_LIMIT_PRIVZETO = 200;
const VSTOPNICE_OFFSET_NAJVEC = 10000000;
const VSTOPNICE_Q_NAJVEC = 64;
function celoIzPoizvedbe(v, najmanj, najvec) {
  if (typeof v !== "string" || !/^[0-9]{1,9}$/.test(v)) return null;
  const n = Number(v);
  return n >= najmanj && n <= najvec ? n : null;
}
app.get("/business/events/:id/tickets", requireAuth, requireClub("owner", "manager", "doorman"), async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    // Vratar (zacasno osebje) ne potrebuje e-naslovov kupcev (najmanj podatkov, GDPR); za rocni vstop zadostujeta
    // podpisan QR in uporabnisko ime. Lastnik in manager vidita vse kot doslej (pregled 5. 10. 2026).
    const vratar = req.klub && req.klub.role === "doorman";
    const ovojnica = ["limit", "offset", "q"].some((k) => req.query[k] !== undefined);
    let limit = VSTOPNICE_LIMIT_NAJVEC, offset = 0, iskanje = null;
    if (ovojnica) {
      limit = VSTOPNICE_LIMIT_PRIVZETO;
      if (req.query.limit !== undefined) {
        limit = celoIzPoizvedbe(req.query.limit, 0, VSTOPNICE_LIMIT_NAJVEC);
        if (limit === null) return res.status(400).json({ error: "invalid_limit", message: `limit must be an integer between 0 and ${VSTOPNICE_LIMIT_NAJVEC}.` });
      }
      if (req.query.offset !== undefined) {
        offset = celoIzPoizvedbe(req.query.offset, 0, VSTOPNICE_OFFSET_NAJVEC);
        if (offset === null) return res.status(400).json({ error: "invalid_offset", message: "offset must be a non-negative integer." });
      }
      if (req.query.q !== undefined) {
        if (typeof req.query.q !== "string") return res.status(400).json({ error: "invalid_q", message: "q must be a single string." });
        const q = req.query.q.trim();
        if (q.length > VSTOPNICE_Q_NAJVEC) return res.status(400).json({ error: "invalid_q", message: `q must be at most ${VSTOPNICE_Q_NAJVEC} characters.` });
        if (/[\u0000-\u001f\u007f]/.test(q)) return res.status(400).json({ error: "invalid_q", message: "q must not contain control characters." });   // NUL bi Postgres zavrnil (500)
        if (q) iskanje = "%" + q.replace(/[\\%_]/g, "\\$&") + "%";
      }
    }
    const iz = `FROM tickets t JOIN orders o ON o.id = t.order_id JOIN events e ON e.id = t.event_id
       LEFT JOIN users u ON u.id = o.user_id ${JOIN_IMETNIK}`;
    const params = [id, klub];
    let pogoj = "t.event_id = $1 AND e.club_id = $2";
    if (iskanje) {
      params.push(iskanje);
      // Samo polja, ki jih vloga vidi v odgovoru (sicer bi iskanje razkrilo, cesar seznam ne): e-naslov samo lastnik/manager in ne pri guest listi.
      pogoj += ` AND (o.public_ref ILIKE $3 ESCAPE '\\' OR t.serial::text ILIKE $3 ESCAPE '\\'
          OR COALESCE(u.username, ${IME_GOSTA}) ILIKE $3 ESCAPE '\\' OR COALESCE(hu.username, ${IME_GOSTA_IMETNIKA}) ILIKE $3 ESCAPE '\\'`
        + (vratar ? ")" : ` OR (o.guest_list_id IS NULL AND (o.buyer_email ILIKE $3 ESCAPE '\\' OR hu.email ILIKE $3 ESCAPE '\\')))`);
    }
    // Ovojnica: seznam in stevci tecejo ZAPOREDNO na eni povezavi glavnega poola (ne dveh), z mejo 3 s (ILIKE brez indeksa; glavni pool sicer
    // nima statement_timeout). Brez ovojnice (star odjemalec) ostane en navaden stavek kot doslej.
    let c = null;
    try {
      if (ovojnica) {
        c = await pool.connect();
        await c.query("BEGIN READ ONLY");
        await c.query("SET LOCAL statement_timeout = 3000");
      }
      const db = c || pool;
      const r = await db.query(
        `SELECT ${STOLPCI_VSTOPNICE}, ${STOLPCI_VIP_VSTOPNICE}, o.public_ref, o.buyer_email, COALESCE(u.username, ${IME_GOSTA}) AS buyer_username, ${STOLPCI_IMETNIKA}, ${SQL_SPOR_ODPRT} AS payment_disputed
         ${iz}
         WHERE ${pogoj} ORDER BY t.id LIMIT ${ovojnica ? limit + 1 : limit} OFFSET ${offset}`, params
      );
      const vrstice = ovojnica ? r.rows.slice(0, limit) : r.rows;
      const vrni = vrstice.map(t => {
        const v = { ...t, qr: qrVstopnice(t) };
        // Guest lista (035): e-naslovov gostitelja in povabljenih prijateljev klub ne vidi (nobena vloga); samo uporabniska imena.
        if (vratar || t.is_guest_list) { delete v.buyer_email; delete v.holder_email; }
        return v;
      });
      if (!ovojnica) return res.json(vrni);
      // Stevci cez VSE vstopnice dogodka (indeks tickets_event_idx); `total` = zadetki iskanja (brez iskanja = vse).
      const st = await db.query(`SELECT t.status, COUNT(*)::int AS n FROM tickets t JOIN events e ON e.id = t.event_id WHERE t.event_id = $1 AND e.club_id = $2 GROUP BY t.status`, [id, klub]);
      const sk = iskanje ? await db.query(`SELECT COUNT(*)::int AS n ${iz} WHERE ${pogoj}`, params) : null;
      await c.query("COMMIT");
      const po = Object.fromEntries(st.rows.map(x => [x.status, x.n]));
      const counts = { all: st.rows.reduce((a, x) => a + x.n, 0), sold: (po.valid || 0) + (po.used || 0), checked_in: po.used || 0,
        expected: po.valid || 0, refunded: po.refunded || 0, void: po.void || 0 };
      const hasMore = limit > 0 && r.rows.length > limit;   // limit=0 = samo stevci: odjemalec se ne sme zacikliti na has_more
      return res.json({ tickets: vrni, counts, total: sk ? sk.rows[0].n : counts.all, limit, offset, has_more: hasMore, next_offset: hasMore ? offset + limit : null });
    } catch (e) {
      if (c) await c.query("ROLLBACK").catch(() => {});
      if (e && e.code === "57014") {
        console.error("[tickets] iskanje je preseglo statement_timeout");
        return res.status(503).set("Retry-After", "5").json({ error: "search_timeout", message: "The ticket list is busy. Try again in a few seconds." });
      }
      throw e;
    } finally { if (c) c.release(); }
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
              e.title AS event_title, e.start_at, e.min_age, o.package_id, (o.guest_list_id IS NOT NULL) AS guest_lista, ${SQL_SPOR_ODPRT} AS payment_disputed
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
    // Spor (chargeback, #278): vstopnica s sporom na vratih ne velja (sken: payment_disputed); prejemnik (prijatelj ali gost) ne sme dobiti
    // vstopnice, ki je ob prihodu neveljavna. Ista koda in besedilo kot pri skenu.
    if (t.payment_disputed) { await c.query("ROLLBACK"); return res.status(409).json({ error: "payment_disputed", result: "payment_disputed", message: "The payment for this ticket is disputed (chargeback). It can't be transferred." }); }

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
    // Blok (041) v obe smeri: prejemnik z racunom, ki je blokiran ali je blokiral posiljatelja, je kot da racuna ni (isto sporocilo kot za neznan e-naslov
    // oz. neprijatelja; tudi nepotrjen racun in allow_guest ne obideta bloka). Pod zaklepom para: blokiranje in prenos se vrstita.
    if (p && Number(p.id) !== Number(req.user.userId)) {
      await zakleniPar(c, req.user.userId, p.id);
      if (await jeBlokiran(c, req.user.userId, p.id)) {
        await c.query("ROLLBACK");
        return res.status(404).send(prejemnikId ? "You can only send a ticket by user to one of your friends." : "No Outly account with this email. Ask your friend to sign up first.");
      }
    }
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
    else void posljiPush([p.id], PUSH.prejetaVstopnica(u.rows[0].id, req.user.username), "ticket_received");   // push poleg zvonca (040), po commitu, brez await
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
    // Blok (041): zaklep vsakega para v narascajocem vrstnem redu (dve vabili hkrati se ne zaklenita v krogu), nato prijateljstvo IN brez bloka v nobeni smeri.
    for (const uid of [...ids].sort((x, y) => x - y)) if (uid !== userId) await zakleniPar(c, userId, uid);
    // Samo prijatelji (gostitelj sam, neznani id-ji in blokirani = ista 403: ne razkrivamo obstoja uporabnikov).
    const fr = await c.query(
      `SELECT u.id, u.username, starost(u.date_of_birth) AS leta FROM users u
        WHERE u.id = ANY($2::int[]) AND u.id <> $1::int
          AND EXISTS (SELECT 1 FROM friendships f WHERE f.user_a = LEAST(u.id, $1::int) AND f.user_b = GREATEST(u.id, $1::int))
          AND NOT EXISTS (SELECT 1 FROM user_blocks b WHERE (b.blocker_id = u.id AND b.blocked_id = $1::int) OR (b.blocker_id = $1::int AND b.blocked_id = u.id))`, [userId, ids]);
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
    const vstopniceVabljenih = [];
    for (const uid of ids) {
      const t = await c.query("INSERT INTO tickets (order_id, event_id, holder_user_id) VALUES ($1, $2, $3) RETURNING id", [l.order_id, l.event_id, uid]);
      await c.query("INSERT INTO guest_list_members (guest_list_id, user_id, ticket_id) VALUES ($1, $2, $3)", [id, uid, t.rows[0].id]);
      vstopniceVabljenih.push([uid, t.rows[0].id]);
    }
    await c.query("COMMIT");
    console.log(`Guest lista ${id}: gostitelj ${userId} je povabil ${ids.length} (dogodek ${l.event_id})`);
    // Push poleg zvonca (040): vsak povabljenec dobi obvestilo z id-jem SVOJE vstopnice (denarnica). Po commitu, brez await.
    for (const [uid, vstopnicaId] of vstopniceVabljenih) void posljiPush([uid], PUSH.vabiloGuestLista(vstopnicaId, req.user.username), "guest_list_invite");
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

// Strezba VIP mize (migracija 038, I27): del istega stavka kot UPDATE vstopnice (CTE `u` = pravkar unovcena vstopnica). Prvi uspesen sken
// katerekoli vstopnice VIP narocila (orders.table_id) vstavi strezbo, naslednji jo zaradi UNIQUE (order_id) preskocijo (ON CONFLICT DO NOTHING).
// En stavek = sken in strezba nastaneta skupaj ali nic (sken, ki uspe, ne more izgubiti strezbe); brez dodatnega kroga do baze na vroci poti.
// Podatki mize in paketa so posnetek iz narocila; kupca tabela ne hrani. Navadno narocilo (table_id IS NULL) in rezervacija po telefonu (ni skena) strezbe ne ustvarita.
const STREZBA_CTE = `s AS (
  INSERT INTO table_service (event_id, order_id, club_id, table_label, table_seats, package_name, package_description, scanned_at)
  SELECT o.event_id, o.id, e.club_id, o.table_label, o.table_seats, o.package_name, o.package_description, u.used_at
    FROM u JOIN orders o ON o.id = u.order_id JOIN events e ON e.id = o.event_id
   WHERE o.table_id IS NOT NULL
  ON CONFLICT (order_id) DO NOTHING RETURNING id)`;

// POST /business/tickets/scan — skener na vratih. Telo: { qr } (ali { serial } za ročni vnos), neobvezno client_scan_id.
// Preveri podpis, lastništvo, stanje; vstopnico označi kot uporabljeno. Ponovni sken -> 409.
// Idempotentnost (#308, po vzoru scan-batch): odjemalec za en poskus vpisa ustvari client_scan_id (UUID) in ga ob ponovitvi
// (izgubljen odgovor, timeout) poslje enakega. V tickets.scan_device ostane zaznamek "scan|<client_scan_id>" (namesto user-agenta).
// Ponovitev = isti zaznamek IN isti uporabnik IN najvec SKEN_PONOVITEV_MS po vpisu -> 200 "ok" z izvirnim used_at (replayed: true);
// drug id, brez id ali kasneje -> 409 already_used. Casovna meja omeji skodo hrosca odjemalca, ki bi isti id poslal za vec skenov
// (kopija vstopnice bi sicer dobila "ok"); izgubljen odgovor se ponovi v sekundah.
// Brez polja (stari odjemalci) je vedenje enako kot prej. Neveljaven client_scan_id sken NE zavrne (vrata ne smejo pasti zaradi napake
// odjemalca): prezre se (staro vedenje) in odgovor ima client_scan_id_ignored: true. Brez zaklepov in brez dodatnega kroga do baze na uspesni poti.
app.post("/business/tickets/scan", requireAuthSken, requireClubSken("owner", "manager", "doorman"), async (req, res) => {
  try {
    const b = req.body || {};
    // null/odsotno = staro vedenje. Neveljaven format (napacen tip, prazen, predolg, drugi znaki) se PREZRE: sken poteka kot brez polja,
    // odgovor dobi client_scan_id_ignored: true (vidno ob razvoju), gost na vratih pa ni zavrnjen zaradi napake odjemalca.
    let zaznamek = null, idPrezrt = false;
    if (b.client_scan_id !== undefined && b.client_scan_id !== null) {
      if (typeof b.client_scan_id === "string" && SKEN_ID_VZOREC.test(b.client_scan_id)) zaznamek = `scan|${b.client_scan_id}`;
      else idPrezrt = true;
    }
    const json = (status, telo) => res.status(status).json(idPrezrt ? { ...telo, client_scan_id_ignored: true } : telo);
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
              ${STOLPCI_IMETNIKA}, ${SQL_SPOR_ODPRT} AS payment_disputed, t.scan_device AS zaznamek_skena, t.used_by_user_id AS skeniral_id
       FROM tickets t JOIN events e ON e.id = t.event_id JOIN orders o ON o.id = t.order_id ${JOIN_IMETNIK} WHERE t.serial = $1`, [serial]
    );
    if (r.rows.length === 0) return res.status(404).json({ result: "unknown", message: "Ticket not found." });
    // zaznamek_skena (user-agent ali zaznamek) in skeniral_id sta notranja: ne gresta v odgovor (`ticket: t`).
    const { zaznamek_skena, skeniral_id, ...t } = r.rows[0];
    // Ponovitev istega poskusa (#308): isti zaznamek IN isti uporabnik (zaznamek izbere odjemalec; kot jePonovitev v scan-batch).
    const jePonovitev = (zap, uid, usedAt) => zaznamek !== null && zap === zaznamek && uid !== null && uid !== undefined && Number(uid) === Number(req.user.userId)
      && usedAt instanceof Date && Date.now() - usedAt.getTime() <= SKEN_PONOVITEV_MS;
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
    if (t.status === "used") {
      if (jePonovitev(zaznamek_skena, skeniral_id, t.used_at)) return res.status(200).json({ result: "ok", message: "Welcome in.", used_at: t.used_at, ticket: t, table_service_created: false, replayed: true });
      return json(409, { result: "already_used", message: "Ticket was already scanned.", used_at: t.used_at, ticket: t });
    }
    if (t.status !== "valid") return res.status(409).json({ result: t.status, message: `Ticket is ${t.status}.`, ticket: t });
    // Spor (chargeback) na naroceno: vstopnica ne velja (#190). Ze uporabljena vstopnica ostane »already_used« (zgoraj).
    if (t.payment_disputed) return res.status(409).json({ result: "payment_disputed", message: "The payment for this ticket is disputed (chargeback). Do not admit; send the guest to the club manager.", ticket: t });
    // Casovno okno (I25, Martin 8. 10. 2026): dogodek je aktiven od 12 h pred zacetkom do 6 h po koncu. Isto pravilo imata odjemalca;
    // streznik ga uveljavi tudi za starejse gradnje in kode brez `e`. Brez nove poizvedbe: start_at/end_at sta ze v vrstici.
    if (!jeVOknuSkena(t.start_at, t.end_at, Date.now())) return res.status(409).json({ result: "not_today", message: "This ticket is not for today's event.", ticket: t });

    // Pogoj serial=$4: če je bila vstopnica med branjem zgoraj in tem UPDATE-om
    // prenesena prijatelju (prenos ji da NOV serial), stara koda ne sme več
    // veljati — sicer bi pošiljatelj vstopil s staro kodo, prejemnik pa bi
    // dobil že porabljeno vstopnico (ugotovljeno s testom sočasnosti).
    const u = await skenPool.query(
      `WITH u AS (
         UPDATE tickets SET status='used', used_at=NOW(), used_by_user_id=$2, scan_device=$3
          WHERE id=$1 AND status='valid' AND serial=$4 RETURNING id, serial, status, used_at, order_id),
       ${STREZBA_CTE}
       SELECT u.id, u.serial, u.status, u.used_at, EXISTS (SELECT 1 FROM s) AS table_service_created, (SELECT id FROM s) AS table_service_id FROM u`,
      [t.id, req.user.userId, zaznamek ?? String(req.headers["user-agent"] || "").slice(0, 100), serial]
    );
    if (u.rows.length === 0) {
      const z = await skenPool.query(`SELECT status, serial, used_at, used_by_user_id, scan_device FROM tickets WHERE id=$1`, [t.id]);
      const s = z.rows[0];
      if (s && s.serial !== serial) return res.status(409).json({ result: "transferred", message: "This ticket was passed on to someone else. Ask them to show their new code." });
      // Socasna ponovitev z istim client_scan_id (prvi zahtevek je zapisal vmes): tudi ta dobi "ok" z izvirnim used_at.
      if (s && s.status === "used" && jePonovitev(s.scan_device, s.used_by_user_id, s.used_at)) {
        return res.status(200).json({ result: "ok", message: "Welcome in.", used_at: s.used_at, ticket: { ...t, status: "used", used_at: s.used_at }, table_service_created: false, replayed: true });
      }
      return json(409, { result: "already_used", message: "Ticket was already scanned.", ...(s && s.status === "used" ? { used_at: s.used_at } : {}) });
    }
    const { table_service_created, table_service_id, ...tu } = u.rows[0];
    json(200, { result: "ok", message: "Welcome in.", used_at: tu.used_at, ticket: { ...t, ...tu }, table_service_created });
    // Push natakarju (040, I29): SAMO po odgovoru, brez await, mimo skenPool (poizvedbe prejemnikov gredo na glavni pool). Sken ne caka na push in ne pade zaradi njega.
    if (table_service_id) void pushStrezba(klub, [table_service_id]);
    return;
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
app.get("/business/scan-key", requireAuthSken, requireClubSken("owner", "manager", "doorman"), (req, res) => {
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
app.get("/business/events/:id/scan-list", requireAuthSken, requireClubSken("owner", "manager", "doorman"), async (req, res) => {
  try {
    const id = celoId4(req.params.id);
    if (!id) return res.status(400).json({ error: "invalid_id", message: "Invalid event id." });
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).json({ error: "not_found", message: "Club not found." });
    const ev = await skenPool.query("SELECT id, club_id FROM events WHERE id = $1", [id]);
    if (ev.rows.length === 0 || Number(ev.rows[0].club_id) !== Number(klub)) {
      return res.status(404).json({ error: "not_found", message: "Event not found." });
    }
    // En velik stavek (do ~20 000 vstopnic): visja meja stavka v svoji transakciji (skenBranje), ne 503 na hladni pocasni bazi.
    if (skenSeznamovTece >= SKEN_SEZNAM_HKRATI) {
      console.error(`[sken] scan-list zavrnjen: ze ${skenSeznamovTece} hkrati (meja ${SKEN_SEZNAM_HKRATI}, povezava ostane skenu)`);
      return res.status(503).set("Retry-After", "5").json({ error: "service_unavailable", message: "Service temporarily unavailable. Please try again." });
    }
    skenSeznamovTece++;
    let vst, prenosi;
    try {
      [vst, prenosi] = await skenBranje(async (c) => [
      await c.query(
        `SELECT t.serial,
                CASE WHEN o.status IN ('paid','partially_refunded') OR t.status IN ('refunded','void') THEN
                       (CASE WHEN t.status = 'valid' AND ${SQL_SPOR_ODPRT} THEN 'unpaid' ELSE t.status END)   -- #190: spor na naroceno: stari odjemalci »unpaid« kazejo rdece
                     ELSE 'unpaid' END AS status,
                ${SQL_SPOR_ODPRT} AS payment_disputed, t.used_at, (o.table_id IS NOT NULL) AS is_vip, o.table_label, o.package_name,
                COALESCE(hu.username, ${IME_GOSTA_IMETNIKA}) AS holder_username, ${GUEST_LISTA_POLJA}
         FROM tickets t JOIN orders o ON o.id = t.order_id ${JOIN_IMETNIK}
         WHERE t.event_id = $1
         ORDER BY t.id`, [id]),
      await c.query(
        `SELECT tt.old_serial FROM ticket_transfers tt JOIN tickets t ON t.id = tt.ticket_id
         WHERE t.event_id = $1 ORDER BY tt.id`, [id]),
      ]);
    } finally { skenSeznamovTece--; }
    const kid = qrKljuci().kid;
    const tickets = vst.rows.map(t => ({
      serial: t.serial, status: t.status, payment_disputed: t.payment_disputed, used_at: t.used_at, is_vip: t.is_vip, table_label: t.table_label || null,
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
// POST /scan (#308): ponovitev istega client_scan_id velja kot "ok" samo toliko casa po vpisu (izgubljen odgovor se ponovi v sekundah).
const SKEN_PONOVITEV_MS = 10 * 60 * 1000;
const SERIAL_VZOREC = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const jsonVelik = express.json({ limit: "1mb" });
// Rok paketa ob zasedeni bazi (S1, 17. 10. 2026): ko je element ze padel z zacasno napako baze (zaklep vrstice -> lock_timeout) in paket
// tece dlje od SKEN_BATCH_ROK_MS, se ostali elementi ne poskusajo vec (result "error", odjemalec jih obdrzi v vrsti in poslje znova).
// Sicer bi 500 zaklenjenih vrstic pomenilo 500 x lock_timeout. Normalen paket (brez napak) roka nima. 0 = rok izklopljen (vsak element
// se poskusi, tudi po napakah; kot drugje 0 = izklop).
const SKEN_BATCH_ROK_MS = okoljeCelo("SKEN_BATCH_ROK_MS", 5000, 0, 120000);
const SKEN_BATCH_MAJHEN = 20;   // do toliko razlicnih serialov se paket bere brez transakcije (glej beriPaket)
app.post("/business/tickets/scan-batch", requireAuthSken, requireClubSken("owner", "manager", "doorman"), jsonVelik, async (req, res) => {
  const zacetekPaketa = Date.now();
  let zasedenaBaza = false;   // vsaj en element je padel z zacasno napako baze
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
    // Majhen paket (iOS hitra pot: 1 element, rok odjemalca 2 s): brez transakcije, stavka na skenPool z obicajno mejo (5 s) - vsaka
    // dodatna krozna pot (BEGIN/SET/COMMIT) je cakanje na vratih. Velik paket (do 500 serialov): skenBranje z visjo mejo stavka.
    const beriPaket = serijski.length > SKEN_BATCH_MAJHEN ? skenBranje : (fn) => fn(skenPool);
    if (serijski.length) await beriPaket(async (c) => {
      const r = await c.query(
        `SELECT t.id, t.serial, t.status, t.used_at, t.used_by_user_id, t.scan_device, t.event_id, t.created_at, e.club_id, e.start_at, e.end_at, e.status AS event_status, o.status AS order_status, ${SQL_SPOR_ODPRT} AS payment_disputed
         FROM tickets t JOIN events e ON e.id = t.event_id JOIN orders o ON o.id = t.order_id
         WHERE t.serial = ANY($1::uuid[])`, [serijski]);
      for (const t of r.rows) vrstice.set(t.serial, t);
      const neznani = serijski.filter(s => !vrstice.has(s));
      if (neznani.length) {
        const p = await c.query(
          `SELECT tt.old_serial, e.club_id FROM ticket_transfers tt JOIN tickets t ON t.id = tt.ticket_id JOIN events e ON e.id = t.event_id
           WHERE tt.old_serial = ANY($1::uuid[])`, [neznani]);
        for (const x of p.rows) prenesene.set(x.old_serial, x.club_id);
      }
    });

    const iso = (d) => (d ? new Date(d).toISOString() : null);
    const strezbeZaPush = [];   // nove strezbe tega paketa; push (040) gre sele po odgovoru
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
      if (zasedenaBaza && SKEN_BATCH_ROK_MS > 0 && Date.now() - zacetekPaketa > SKEN_BATCH_ROK_MS) {
        rezultati[d.i] = { client_scan_id: d.cid, serial: d.serial, result: "error", used_at: null };
        continue;
      }
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
        else if (t.payment_disputed) rez = { result: "payment_disputed", used_at: null };
        else if (!jeVOknuSkena(t.start_at, t.end_at, casSkena(d.kdaj, t))) rez = { result: "not_today", used_at: null };
        else {
          // used_at = ura na telefonu, če je razumna: ne v prihodnosti, ne pred nastankom vstopnice, ne prej kot 12 h pred začetkom dogodka.
          // Pogoj serial = $4 kot pri /scan: prenos med branjem in pisanjem da vstopnici nov serial, stara koda ne sme več veljati.
          const u = await skenPool.query(
            `WITH u AS (
               UPDATE tickets SET status = 'used',
                      used_at = CASE WHEN $5::timestamptz IS NOT NULL AND $5::timestamptz <= NOW()
                                      AND $5::timestamptz >= GREATEST(created_at, $6::timestamptz)
                                     THEN $5::timestamptz ELSE NOW() END,
                      used_by_user_id = $2, scan_device = $3
               WHERE id = $1 AND status = 'valid' AND serial = $4::uuid RETURNING used_at, order_id),
             ${STREZBA_CTE}
             SELECT u.used_at, EXISTS (SELECT 1 FROM s) AS table_service_created, (SELECT id FROM s) AS table_service_id FROM u`,
            [t.id, req.user.userId, d.zaznamek, d.serial, d.kdaj, new Date(new Date(t.start_at).getTime() - SKEN_REZERVA_PRED_ZACETKOM_MS).toISOString()]);
          if (u.rows.length) {
            t.status = "used"; t.scan_device = d.zaznamek; t.used_at = u.rows[0].used_at; t.used_by_user_id = req.user.userId;
            rez = { result: "ok", used_at: iso(t.used_at), table_service_created: u.rows[0].table_service_created };
            if (u.rows[0].table_service_id) strezbeZaPush.push(u.rows[0].table_service_id);
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
        if (jeZacasnaNapaka(e)) zasedenaBaza = true;
        rez = { result: "error", used_at: null };
      }
      rezultati[d.i] = { client_scan_id: d.cid, serial: d.serial, ...rez };
    }
    const stevilo = (r) => rezultati.filter(x => x.result === r).length;
    console.log(`Sken-batch: klub ${klub}, uporabnik ${req.user.userId}: ${n} skenov, ok ${stevilo("ok")}, already_used ${stevilo("already_used")}, transferred ${stevilo("transferred")}, not_today ${stevilo("not_today")}, error ${stevilo("error")}`);
    res.status(200).json({ results: rezultati });
    if (strezbeZaPush.length) void pushStrezba(klub, strezbeZaPush);   // po odgovoru, brez await (I29)
    return;
  } catch (e) { return odgovoriNaNapako(res, e, "POST /business/tickets/scan-batch"); }
});

// ---------------------------
// STREZBA VIP MIZ (migracija 038, invarianta I27; issue #176, Martin 9. 10. 2026)
// ---------------------------
// Strezba nastane SAMO iz skena VIP vstopnice (STREZBA_CTE v /scan in scan-batch), nikoli iz nakupa ali rezervacije po telefonu. Natakar (bartender),
// manager in lastnik jo vidijo in oznacijo kot dostavljeno; vratar ne. Odgovori nosijo SAMO mizo, sedeze, paket, opis in case (+ uporabnisko ime
// ZAPOSLENEGA, ki je dostavil), nikoli kupca ali imetnika vstopnice: stolpci so naštevani, tabela kupca ne hrani.
const STREZBA_STOLPCI = `ts.id, ts.order_id, ts.table_label, ts.table_seats, ts.package_name, ts.package_description, ts.scanned_at, ts.delivered_at,
  du.username AS delivered_by_username`;
const STREZBA_IZ = `FROM table_service ts LEFT JOIN users du ON du.id = ts.delivered_by_user_id`;

// GET /business/events/:id/table-service — owner, manager, bartender (vratar 403). Tuj ali neobstojec dogodek: 404.
// Nedostavljene najprej (po scanned_at), nato dostavljene (po scanned_at).
app.get("/business/events/:id/table-service", requireAuth, requireClub("owner", "manager", "bartender"), async (req, res) => {
  try {
    const id = celoId4(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const e = await pool.query("SELECT 1 FROM events WHERE id = $1 AND club_id = $2", [id, klub]);
    if (!e.rows.length) return res.status(404).send("Event not found.");
    const r = await pool.query(
      `SELECT ${STREZBA_STOLPCI} ${STREZBA_IZ}
        WHERE ts.event_id = $1 AND ts.club_id = $2
        ORDER BY (ts.delivered_at IS NOT NULL), ts.scanned_at, ts.id LIMIT 500`, [id, klub]);
    return res.json({ items: r.rows });
  } catch (e) { return odgovoriNaNapako(res, e, "GET /business/events/:id/table-service"); }
});

// PUT /business/table-service/:id { delivered: boolean } — owner, manager, bartender. Vrne posodobljen element (brez ovojnice).
// true je idempotenten (cas in dostavitelj prvega klica ostaneta), false razveljavi. Strezba tujega kluba: 404.
app.put("/business/table-service/:id", requireAuth, requireClub("owner", "manager", "bartender"), async (req, res) => {
  try {
    const id = celoId4(req.params.id);
    if (!id) return res.status(400).send("Invalid id.");
    const b = req.body;
    if (!b || typeof b !== "object" || typeof b.delivered !== "boolean") return res.status(400).send("delivered must be true or false.");
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const r = await pool.query(
      `WITH u AS (
         UPDATE table_service SET
                delivered_at = CASE WHEN $3::boolean THEN COALESCE(delivered_at, NOW()) END,
                delivered_by_user_id = CASE WHEN $3::boolean THEN COALESCE(delivered_by_user_id, $4::int) END
          WHERE id = $1 AND club_id = $2 RETURNING *)
       SELECT ${STREZBA_STOLPCI} FROM u ts LEFT JOIN users du ON du.id = ts.delivered_by_user_id`,
      [id, klub, b.delivered, req.user.userId]);
    if (!r.rows.length) return res.status(404).send("Not found.");
    console.log(`Strezba ${id}: ${b.delivered ? "dostavljeno" : "razveljavljeno"}, klub ${klub}, uporabnik ${req.user.userId}`);
    return res.json(r.rows[0]);
  } catch (e) { return odgovoriNaNapako(res, e, "PUT /business/table-service/:id"); }
});

// GET /me/table-service — zvonec natakarja/managerja/lastnika: nedostavljene strezbe vseh njegovih klubov za dogodke, ki tecejo (isti pogoj kot
// pending_table_service v GET /me). Vloge iz baze ob vsakem klicu (I5); za vse ostale 200 s praznim seznamom.
app.get("/me/table-service", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT ts.id, ts.club_id, c.name AS club_name, ts.event_id, e.title AS event_title, ts.table_label, ts.package_name, ts.scanned_at
         ${STREZBA_ZVONEC_IZ} ${STREZBA_ZVONEC_KJE}
        ORDER BY ts.scanned_at, ts.id LIMIT 100`, [req.user.userId]);
    return res.json({ items: r.rows });
  } catch (e) { return odgovoriNaNapako(res, e, "GET /me/table-service"); }
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

// Skupna validacija tlorisa in miz (PUT /business/vip in PUT /business/events/:id/vip-layout, 039): mreza 8-40, elementi <= 80, mize <= 60,
// seats 1-20, cene v centih >= 0, oznake unikatne. Vrne { plan, mize } (ociscene kopije) ali { napaka }.
function preveriRazpored(planVhod, mizeVhod) {
  const tl = preveriTloris(planVhod);
  if (tl.napaka) return { napaka: tl.napaka };
  const mz = preveriMize(mizeVhod, tl.plan);
  if (mz.napaka) return { napaka: mz.napaka };
  return { plan: tl.plan, mize: mz.mize };
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
       FROM club_tables WHERE club_id = $1 AND event_id IS NULL AND archived_at IS NULL ORDER BY id`, [klub]);
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
  const rz = preveriRazpored(b.plan, b.tables);
  if (rz.napaka) return res.status(400).send(rz.napaka);
  const tl = { plan: rz.plan }, mz = { mize: rz.mize };
  const pk = preveriPakete(b.packages);
  if (pk.napaka) return res.status(400).send(pk.napaka);

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    // NO KEY UPDATE (ne UPDATE): nakup mize med transakcijo bere klub prek tujega kljuca (KEY SHARE)
    // in bi se s polnim zaklepom zaciklal (mrtva zanka).
    await c.query("SELECT id FROM clubs WHERE id = $1 FOR NO KEY UPDATE", [klub]);

    // --- mize ---
    // event_id IS NULL: mize razporeda posameznih dogodkov (039) niso del klubskega tlorisa in jih ta PUT ne sme arhivirati.
    const obst = await c.query("SELECT id FROM club_tables WHERE club_id = $1 AND event_id IS NULL AND archived_at IS NULL", [klub]);
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
  const e = await db.query("SELECT id, vip_enabled, currency, vip_layout_source, floor_plan FROM events WHERE id = $1 AND club_id = $2", [eventId, klub]);
  if (e.rows.length === 0) return null;
  const razporedDogodka = e.rows[0].vip_layout_source === "event";   // 039: tloris in mize dogodka namesto klubskih
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
      -- Aktivne mize veljavnega razporeda (klubske ali dogodka, 039) + vsaka miza (tudi arhivirana ali iz drugega razporeda) z narocilom/rezervacijo na tem dogodku.
      WHERE ct.club_id = $2 AND (ct.event_id IS NULL OR ct.event_id = $1)
        AND ((ct.archived_at IS NULL AND (ct.event_id IS NOT NULL) = $3::boolean) OR b.order_id IS NOT NULL OR h.id IS NOT NULL)
      ORDER BY ct.id`, [eventId, klub, razporedDogodka]);
  const p = await db.query(
    `SELECT id, name, description FROM bottle_packages
      WHERE club_id = $1 AND archived_at IS NULL ORDER BY sort, id`, [klub]);
  return {
    event_id: e.rows[0].id,
    enabled: e.rows[0].vip_enabled,
    currency: e.rows[0].currency,
    plan: (razporedDogodka ? e.rows[0].floor_plan : (k.rows[0] && k.rows[0].floor_plan)) || null,
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

// GET /business/events/:id/vip — lastnik, manager in vratar (vratar mora videti rezervacije). Natakar NE (038, I27): booking nosi uporabnisko ime kupca,
// rezervacija po telefonu pa ime gosta; natakar strezbo dobi iz GET /business/events/:id/table-service.
// Tuj ali neobstojec dogodek: 404 (ne razkrivamo obstoja).
app.get("/business/events/:id/vip", requireAuth, requireClub("owner", "manager", "doorman"), async (req, res) => {
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
      // Razpored dogodka (039): izjeme veljajo tudi za mize TEGA dogodka (event_id = :id); miza drugega dogodka istega kluba je 404.
      const v = await c.query(
        "SELECT id, event_id, archived_at IS NOT NULL AS arhivirana FROM club_tables WHERE club_id = $1 AND id = ANY($2::int[])",
        [klub, izjeme.map(t => t.table_id)]);
      const mize = new Map(v.rows.map(r => [r.id, r.arhivirana]));
      const slaba = izjeme.find(t => !mize.has(t.table_id));
      if (slaba) { await c.query("ROLLBACK"); return res.status(400).send(`tables: id ${slaba.table_id} does not belong to this club.`); }
      if (v.rows.some(r => r.event_id !== null && r.event_id !== id)) { await c.query("ROLLBACK"); return res.status(404).send("Table not found."); }
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
// RAZPORED VIP MIZ PO DOGODKU (migracija 039, Martin 9. 10. 2026; issue #175; invarianta I28)
// ---------------------------
// Organizator (clubs.is_organizer) nima lastne dvorane: pri dogodku izbere vir razporeda VIP miz.
//   source 'club'  = tloris in mize kluba prodajalca (club_tables.event_id IS NULL), kot doslej;
//   source 'event' = razpored TEGA dogodka: events.floor_plan + club_tables z event_id = dogodek (club_id = events.club_id), nastane kot
//                    posnetek tlorisa in miz gostitelja (events.venue_club_id; kasnejse spremembe gostitelja ne vplivajo) ali kot lasten risan razpored.
// Paketi steklenic in denar ostanejo pri prodajalcu; narocila, vstopnice, sken in strezba delajo nespremenjeno (FK orders.table_id -> club_tables).
// Navaden klub sme razpored dogodka prav tako uporabiti (ni izpostavljen v UI). Izjeme po dogodku (event_tables) in rezervacije po telefonu
// delujejo tudi za mize dogodka. Miza z narocilom se ob odstranitvi ARHIVIRA, brez narocila IZBRISE; telefonske rezervacije odstranjenih miz se izbrisejo.

// Odgovor GET/PUT vip-layout: vir, tloris dogodka, mize dogodka (aktivne + arhivirane z aktivnim narocilom, archived: true), kopija in gostitelj.
// Vrne null, ce dogodek ne obstaja ali ni od tega kluba. Gostitelj, ki je skrit, javno ne obstaja (venue_club_id null, brez kopije).
async function vipRazporedOdgovor(db, klub, eventId) {
  const e = await db.query(
    `SELECT e.id, e.vip_layout_source, e.floor_plan, e.vip_layout_from_club_id, fc.name AS from_club_name,
            vc.id AS venue_club_id, vc.name AS venue_club_name, (vc.floor_plan IS NOT NULL) AS venue_has_layout
       FROM events e
       LEFT JOIN clubs fc ON fc.id = e.vip_layout_from_club_id
       LEFT JOIN clubs vc ON vc.id = e.venue_club_id AND NOT vc.hidden
      WHERE e.id = $1 AND e.club_id = $2`, [eventId, klub]);
  if (e.rows.length === 0) return null;
  const m = await db.query(
    `SELECT ct.id, ct.label, ct.x, ct.y, ct.w, ct.h, ct.shape, ct.seats, ct.price_cents, (ct.archived_at IS NOT NULL) AS archived
       FROM club_tables ct
      WHERE ct.event_id = $1
        AND (ct.archived_at IS NULL
             OR EXISTS (SELECT 1 FROM orders o WHERE o.table_id = ct.id AND o.event_id = $1 AND o.status IN ${VIP_ZASEDENA_STANJA}))
      ORDER BY ct.id`, [eventId]);
  const r = e.rows[0];
  return {
    source: r.vip_layout_source,
    floor_plan: r.floor_plan || null,
    tables: m.rows,
    from_club_id: r.vip_layout_from_club_id,
    from_club_name: r.vip_layout_from_club_id ? r.from_club_name : null,
    venue_club_id: r.venue_club_id,
    venue_club_name: r.venue_club_name,
    venue_has_layout: r.venue_club_id !== null && r.venue_has_layout === true,
  };
}

// GET /business/events/:id/vip-layout — owner, manager. Tuj ali neobstojec dogodek: 404.
app.get("/business/events/:id/vip-layout", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const id = vipId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const o = await vipRazporedOdgovor(pool, klub, id);
    if (!o) return res.status(404).send("Event not found.");
    return res.json(o);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// PUT /business/events/:id/vip-layout — owner, manager. Telo:
//   { source: "club" }                                  nazaj na klubski tloris; mize dogodka se arhivirajo (z narocilom) ali izbrisejo
//   { source: "event", copy_from_venue: true }          posnetek tlorisa in aktivnih miz kluba gostitelja (400 brez gostitelja ali brez njegovega tlorisa)
//   { source: "event", floor_plan, tables: [...] }      lasten razpored (validacija kot PUT /business/vip); mize z id se posodobijo,
//                                                       manjkajoce se arhivirajo/izbrisejo, nove se dodajo; floor_plan null + tables [] = prazen zacetek
// Vse v eni transakciji; dogodek je zaklenjen (FOR NO KEY UPDATE), da dva hkratna PUT-a ne prepisujeta drug drugega. Odgovor = GET + released_holds.
app.put("/business/events/:id/vip-layout", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  const id = vipId(req.params.id);
  if (!id) return res.status(400).send("Invalid event id.");
  const klub = await mojKlubId(req);
  if (!klub) return res.status(404).send("Club not found.");
  const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
  if (b.source !== "club" && b.source !== "event") return res.status(400).send('source must be "club" or "event".');
  const izVenue = b.source === "event" && b.copy_from_venue === true;
  let rz = null;
  if (b.source === "event" && !izVenue) {
    if (b.floor_plan === undefined) return res.status(400).send("floor_plan is required (an object or null), or send copy_from_venue: true.");
    if (b.tables === undefined) return res.status(400).send("tables is required (an array).");
    rz = preveriRazpored(b.floor_plan, b.tables);
    if (rz.napaka) return res.status(400).send(rz.napaka);
  }

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const er = await c.query("SELECT id FROM events WHERE id = $1 AND club_id = $2 FOR NO KEY UPDATE", [id, klub]);
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }

    let plan = null, mize = [], izKluba = null;
    if (izVenue) {
      const g = await c.query(
        `SELECT vc.id, vc.floor_plan FROM events e JOIN clubs vc ON vc.id = e.venue_club_id AND NOT vc.hidden WHERE e.id = $1`, [id]);
      if (g.rows.length === 0) { await c.query("ROLLBACK"); return res.status(400).send("This event has no venue club on Outly."); }
      if (!g.rows[0].floor_plan) { await c.query("ROLLBACK"); return res.status(400).send("The venue club has no floor plan."); }
      izKluba = g.rows[0].id;
      plan = g.rows[0].floor_plan;
      const gm = await c.query(
        `SELECT label, x, y, w, h, shape, seats, price_cents FROM club_tables
          WHERE club_id = $1 AND event_id IS NULL AND archived_at IS NULL ORDER BY id`, [izKluba]);
      mize = gm.rows.map(t => ({ id: null, label: t.label, x: t.x, y: t.y, w: t.w, h: t.h, shape: t.shape, seats: t.seats, price_cents: t.price_cents }));
    } else if (rz) {
      plan = rz.plan;
      mize = rz.mize;
    }

    // --- mize dogodka: obstojece (aktivne in arhivirane) ---
    const obst = await c.query("SELECT id, archived_at IS NOT NULL AS arhivirana FROM club_tables WHERE event_id = $1 AND club_id = $2", [id, klub]);
    const aktivne = new Set(obst.rows.filter(t => !t.arhivirana).map(t => t.id));
    const arhivirane = new Set(obst.rows.filter(t => t.arhivirana).map(t => t.id));
    const vhodne = [];
    for (const t of mize) {
      if (t.id !== null && arhivirane.has(t.id)) continue;   // arhivirano mizo odjemalec lahko poslje nazaj (GET jo vrne): preskoci se
      if (t.id !== null && !aktivne.has(t.id)) { await c.query("ROLLBACK"); return res.status(400).send(`tables: id ${t.id} does not belong to this event.`); }
      vhodne.push(t);
    }
    const ostanejo = vhodne.filter(t => t.id !== null).map(t => t.id);
    const odstranjene = [...aktivne].filter(x => !ostanejo.includes(x));
    let sproscene = 0;
    if (odstranjene.length) {
      // Mize niso vec v ponudbi: rezervacije po telefonu se izbrisejo (released_holds), miza z narocilom se arhivira, brez narocila izbrise.
      // Najprej zaklep vrstic (FOR UPDATE ceka nakup z FOR SHARE in rezervacijo z FOR NO KEY UPDATE, nov nakup pa ceka nas): potem je
      // prebrano stanje narocil/rezervacij dokoncno, zato DELETE ne pade na orders.table_id (RESTRICT) in nakup arhivirane/izbrisane mize dobi 404.
      await c.query("SELECT id FROM club_tables WHERE event_id = $1 AND id = ANY($2::int[]) ORDER BY id FOR UPDATE", [id, odstranjene]);
      const h = await c.query("DELETE FROM table_holds WHERE event_id = $1 AND table_id = ANY($2::int[])", [id, odstranjene]);
      sproscene = h.rowCount;
      const z = await c.query("SELECT DISTINCT table_id FROM orders WHERE table_id = ANY($1::int[])", [odstranjene]);
      const znarocili = new Set(z.rows.map(r => r.table_id));
      const zaArhiv = odstranjene.filter(x => znarocili.has(x));
      const zaBris = odstranjene.filter(x => !znarocili.has(x));
      if (zaArhiv.length) await c.query("UPDATE club_tables SET archived_at = NOW() WHERE event_id = $1 AND id = ANY($2::int[])", [id, zaArhiv]);
      if (zaBris.length) await c.query("DELETE FROM club_tables WHERE event_id = $1 AND id = ANY($2::int[])", [id, zaBris]);
    }
    // Zacasne oznake: zamenjava oznak med dvema mizama (T1 <-> T2) bi sicer trcila ob unikatnem indeksu.
    if (ostanejo.length) await c.query("UPDATE club_tables SET label = '~' || id WHERE event_id = $1 AND id = ANY($2::int[])", [id, ostanejo]);
    for (const t of vhodne) {
      if (t.id !== null) {
        await c.query(
          `UPDATE club_tables SET label=$3, x=$4, y=$5, w=$6, h=$7, shape=$8, seats=$9, price_cents=$10
            WHERE id=$1 AND event_id=$2`,
          [t.id, id, t.label, t.x, t.y, t.w, t.h, t.shape, t.seats, t.price_cents]);
      } else {
        await c.query(
          `INSERT INTO club_tables (club_id, event_id, label, x, y, w, h, shape, seats, price_cents)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [klub, id, t.label, t.x, t.y, t.w, t.h, t.shape, t.seats, t.price_cents]);
      }
    }

    // --- dogodek: vir, tloris (JSONB prek JSON.stringify), izvor kopije (ostane tudi po rocnem urejanju: zgodovina) ---
    await c.query(
      `UPDATE events SET vip_layout_source = $2, floor_plan = $3::jsonb, vip_layout_from_club_id = COALESCE($4::int, vip_layout_from_club_id) WHERE id = $1`,
      [id, b.source, b.source === "event" && plan !== null ? JSON.stringify(plan) : null, izKluba]);
    await c.query("COMMIT");
    for (const x of odstranjene) razprodanoPozabi("m:" + id + ":" + x);   // nakup, zavrnjen zaradi rezervacije, je mizo oznacil »zasedena« v pomnilniku
    console.log(`Razpored dogodka ${id}: vir ${b.source}${izVenue ? " (kopija gostitelja " + izKluba + ")" : ""}, ${vhodne.length} miz, odstranjenih ${odstranjene.length}, sproscenih rezervacij ${sproscene}`);
    // Branje po COMMIT-u prek istega odjemalca c (glej opombo pri POST /events/:id/orders).
    return res.json({ ...(await vipRazporedOdgovor(c, klub, id)), released_holds: sproscene });
  } catch (err) {
    await c.query("ROLLBACK").catch(() => {});
    if (err && err.code === "23505") return res.status(400).send("Table labels must be unique.");
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
    const er = await c.query(`SELECT id, vip_layout_source, (${KONEC_DOGODKA} <= NOW()) AS koncan FROM events WHERE id = $1 AND club_id = $2`, [id, klub]);
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    // Koncan dogodek (isti izraz kot »ended« drugje): ime gosta se ne shrani brez smisla. Dogodek, ki tece, rezervacijo se sprejme.
    if (er.rows[0].koncan) { await c.query("ROLLBACK"); return res.status(409).send("This event has already ended."); }
    // Miza TEGA kluba, ne arhivirana. Rezervacija je dovoljena tudi, ce je miza na dogodku izklopljena ali VIP na dogodku ni vklopljen
    // (klub tloris uporablja tudi samo za telefonske rezervacije).
    // Razpored dogodka (039): pri vip_layout_source = 'event' je rezervirana miza lahko samo miza TEGA dogodka, sicer samo klubska (event_id IS NULL).
    const mr = await c.query(
      `SELECT id FROM club_tables WHERE id = $1 AND club_id = $2 AND archived_at IS NULL
          AND (CASE WHEN $3::text = 'event' THEN event_id = $4 ELSE event_id IS NULL END) FOR NO KEY UPDATE`, [mizaId, klub, er.rows[0].vip_layout_source, id]);
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
      `SELECT e.id, e.club_id, e.vip_enabled, e.currency, e.status, e.start_at, e.sales_open_at, e.sales_close_at, e.sales_paused, e.min_age,
              e.vip_layout_source, e.floor_plan, c.is_demo, ${sqlPlacilaPripravljena("c.")} AS club_stripe_ready,
              ${sqlProdajalecSurov("c")} AS seller_raw
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
              -- Razpored dogodka (039): mize dogodka (event_id = :id) ali klubske (event_id IS NULL); oblika odgovora je ista.
              WHERE ct.club_id = $2 AND (CASE WHEN $3::text = 'event' THEN ct.event_id = $1 ELSE ct.event_id IS NULL END)
           ) t
          -- Izklopljena ali arhivirana miza je skrita, RAZEN ce je na tem dogodku ze prodana: kupci vidijo "Booked".
          WHERE NOT t.skrita OR t.zasedena
          ORDER BY t.id`, [id, e.club_id, e.vip_layout_source]);
      mize = m.rows;
    }
    const enabled = e.vip_enabled && mize.length > 0;
    let plan = null, paketi = [];
    if (enabled) {
      if (e.vip_layout_source === "event") plan = e.floor_plan || null;
      else {
        const k = await pool.query("SELECT floor_plan FROM clubs WHERE id = $1", [e.club_id]);
        plan = (k.rows[0] && k.rows[0].floor_plan) || null;
      }
      const p = await pool.query(
        `SELECT id, name, description FROM bottle_packages
          WHERE club_id = $1 AND archived_at IS NULL ORDER BY sort, id`, [e.club_id]);
      paketi = p.rows;
    }
    return res.json({
      event_id: e.id,
      enabled,
      on_sale: napakaProdaje({ ...e, hidden: false }, { zahtevajCeno: false }) === null,
      // kot pri dogodku (#149); #220: ob sk_live_ + nepopolnih podatkih prodajalca (I34) "unavailable", razen ce je kupljiva miza za 0 EUR
      // Demo klub (050): "unavailable" (nakup mize je 409 demo_club, razen vloge admin); `is_demo` = prodajalec (events.club_id) je demo klub. Razloga javno ni (I34).
      // Pavza prodaje (055, I53): nakup mize je 409, zato "unavailable" kot pri demo klubu; on_sale je ze false (napakaProdaje).
      payment_mode: e.is_demo || e.sales_paused === true ? "unavailable" : javniNacinProdajalca(placilaStripe.nacinPlacilaZ(e.club_stripe_ready === true), e.seller_raw,
        Math.max(0, ...mize.map(t => Number(t.price_cents) || 0)), mize.some(t => t.available !== false && Number(t.price_cents) === 0)),
      is_demo: e.is_demo === true,
      seller: prodajalec(e.seller_raw),   // prodajalec = events.club_id (043, #94)
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
  const pogoji = pogojiIzTela(b);
  if (pogoji.napaka) return res.status(400).send(pogoji.napaka);
  if (!(await nakupDovoljenje(req, res))) return;
  let c;
  try { c = await pool.connect(); } catch (err) { nakupIzstopi(); console.error(err); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
  const d = nakupDrzalec(c);
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
      `SELECT e.id, e.club_id, e.title, e.status, e.start_at, e.min_age, e.currency, e.vip_enabled, e.vip_layout_source, e.sales_paused,
              e.sales_open_at, e.sales_close_at, e.vat_rate, c.hidden, c.stripe_account_id, c.stripe_charges_enabled, c.stripe_account_livemode, c.commission_bps,
              c.legal_name, c.legal_address, c.registration_number, c.tax_number, c.vat_payer, c.contact_phone, c.contact_email, c.is_demo, c.is_official
         FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1`, [id]);
    // Brez zaklepa dogodka tu (pregled #316 M10): zaklep vrstice dogodka PRED advisory zaklepi uporabnika (omejitevBrezplacnih/omejitevCakajocih) bi bil obraten
    // vrstni red kot pri nakupu vstopnic (advisory, nato dogodek v sprozilcu) -> mrtva zanka istega kupca. Pavzo pred COMMIT-om preveri pavzaPredCommitom (M2).
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    const e = er.rows[0];
    // Demo klub (050): 409 PRED mizo, zalogo in Stripom; izjema vloga admin.
    const demo = napakaDemoKluba(e, req.user.role);
    if (demo) { await c.query("ROLLBACK"); return res.status(409).json(demo); }
    if (e.status !== "published" || e.hidden) { await c.query("ROLLBACK"); return res.status(409).send("Event is not on sale."); }
    if (!e.vip_enabled) { await c.query("ROLLBACK"); return res.status(404).send("Table not found."); }

    // Miza: aktivna, od kluba dogodka in na tem dogodku ne izklopljena. FOR SHARE: cena in stanje mize se
    // med nakupom ne smeta spremeniti (PUT /business/vip jo posodablja, ta zahteva izkljucni zaklep vrstice).
    const mr = await c.query(
      `SELECT ct.id, ct.label, ct.seats, COALESCE(et.price_cents, ct.price_cents) AS price_cents
         FROM club_tables ct LEFT JOIN event_tables et ON et.event_id = $1 AND et.table_id = ct.id
        WHERE ct.id = $2 AND ct.club_id = $3 AND ct.archived_at IS NULL AND NOT COALESCE(et.disabled, FALSE)
          -- Razpored dogodka (039): miza mora biti iz veljavnega razporeda (miza drugega dogodka ali klubska pri razporedu dogodka = 404).
          AND (CASE WHEN $4::text = 'event' THEN ct.event_id = $1 ELSE ct.event_id IS NULL END)
        FOR SHARE OF ct`, [e.id, mizaId, e.club_id, e.vip_layout_source]);
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
    const test = nacin === "test";
    const cena = miza.price_cents;
    const npk = napakaKlubaBrezStripa(nacin, cena);   // I49: klub brez Stripa zavrne samo placljivo
    if (npk) { await c.query("ROLLBACK"); return res.status(409).send(npk); }
    const np2 = napakaProdajalca(e, nacin, cena);
    if (np2) { await c.query("ROLLBACK"); return res.status(409).json(np2); }
    const placanoTakoj = test || cena === 0;   // miza za 0 EUR gre mimo Stripa (#191), kot vstopnice
    if (cena === 0) {
      const brezplacno = await omejitevBrezplacnih(c, { userId: req.user.userId, eventId: e.id, enot: 1 });
      if (brezplacno) { await c.query("ROLLBACK"); return res.status(409).json(brezplacno); }
    }
    if (!placanoTakoj) {
      const omejitev = await omejitevCakajocih(c, req.user.userId, e.id);
      if (omejitev) { await c.query("ROLLBACK"); return res.status(409).send(omejitev); }
    }

    const platformno = placilaStripe.jePlatformniProdajalec(e);   // I50: kot pri vstopnicah
    const provizija = platformno ? 0 : provizijaCentov(cena, e.commission_bps);
    const ref = javnaRef();
    const pi = test ? "test_" + crypto.randomUUID() : null;

    // Sprozilec orders_rezerviraj narocilo z mizo preskoci (ne steje v capacity). Zasedenost mize varuje
    // unikaten indeks orders_miza_dogodek_key (I13): ob hkratnem nakupu druga vstavitev pade z 23505.
    const or = await c.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency,
                           application_fee_cents, vat_rate, status, stripe_payment_intent_id, buyer_email, paid_at,
                           table_id, table_label, table_seats, package_id, package_name, package_description, idempotency_key,
                           stripe_account_id, receipt_mail_attempts, terms_version, terms_accepted_at)
       VALUES ($1,$2,$3,$4,1,$5,$5,$6,$7,$8,$18,$9,$10,CASE WHEN $18 = 'paid' THEN NOW() END,$11,$12,$13,$14,$15,$16,$17,$19,CASE WHEN $18 = 'paid' THEN 0 END,$20::text,CASE WHEN $20::text IS NOT NULL THEN NOW() END) RETURNING id`,
      [ref, req.user.userId, e.id, e.club_id, cena, e.currency, provizija, e.vat_rate, pi, starost.email,
       miza.id, miza.label, miza.seats, paket ? paket.id : null, paket ? paket.name : null, paket ? paket.description : null,
       req.idemKljuc || null, placanoTakoj ? "paid" : "pending", placilaStripe.racunNarocila(placanoTakoj, platformno, e.stripe_account_id), pogoji.verzija]
    );
    const oid = or.rows[0].id;
    if (placanoTakoj) await c.query(`INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [oid, e.id, miza.seats]);
    if (await pavzaPredCommitom(c, e.id)) { await c.query("ROLLBACK"); return res.status(409).send(NAPAKA_PAVZA_PRODAJE); }   // M2, I53
    await c.query("COMMIT");
    opozoriPogoje("POST /events/:id/tables/:tableId/orders", pogoji.verzija, ref);

    // Branje po COMMIT-u prek odjemalca c, NE prek pool (glej opombo pri POST /events/:id/orders); Stripe pot (#274) sprosti c in dovoljenje takoj.
    const telo = placanoTakoj ? await odgovorNarocila(c, oid)
      : await nakupStripeSeja(res, d, { oid, opis: `${e.title} – VIP ${miza.label}${paket ? " + " + paket.name : ""}`,
        kolicina: 1, cenaEnoteCents: cena, racunKluba: platformno ? null : e.stripe_account_id, platformno, email: starost.email, eventId: e.id, odjemalec: odjemalecNakupa(req), locale: localeNakupa(req) });
    if (!telo) return;
    console.log(`Nakup mize (${placanoTakoj && !test ? "brezplacno" : nacin}): naročilo ${ref}, uporabnik ${req.user.userId}, dogodek ${e.id}, miza ${miza.id}, ${miza.seats} vstopnic, ${cena} c`);
    if (placanoTakoj) posljiPotrdiloKupcu(oid);   // brez await (kot pri vstopnicah)
    return res.status(201).json(telo);
  } catch (err) {
    if (d.drzi) await c.query("ROLLBACK").catch(() => {});   // po sprostitvi (nakupStripeSeja, #274) c ni vec nas
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
  } finally { try { d.sprosti(); } finally { if (req.idem) req.idem.sprosti(); } }
});

// ---------------------------
// EKIPA KLUBA (migracija 009)
// ---------------------------
// Lastnik vabi managerje, vratarje in natakarje (bartender, 038); manager sme vabiti in odstranjevati
// samo vratarje in natakarje. Od migracije 013 je dodajanje VABILO: uporabnik ga sprejme ali
// zavrne v aplikaciji (My clubs -> zvonec), član nastane ob sprejemu. Povabljeni
// mora že imeti Outly račun (po e-naslovu). Sodelavec je lahko v največ eni
// ekipi in lastnik kluba ne more biti hkrati član druge.
const VLOGE_EKIPE = ["manager", "doorman", "bartender"];
// Osebje, ki ga sme vabiti in odstranjevati tudi manager (manager le osebje, managerja samo lastnik).
const VLOGE_OSEBJE = ["doorman", "bartender"];

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
  const vloga = role === "manager" ? "manager" : role === "bartender" ? "bartender" : "door staff";
  try {
    const r = await resend.emails.send({
      from, to: toEmail,
      subject: zadevaMaila(`${clubName} invited you to their team on ${appName}`),
      html: nogaMaila({ html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${ubeziHtml(appName)} – Club team</h2>
      <p><b>${ubeziHtml(clubName)}</b> has invited you to work with them as <b>${vloga}</b>.</p>
      <p>Open the ${ubeziHtml(appName)} app, go to <b>Profile → My clubs</b> and tap the bell to accept or reject the invitation.</p>
      <p>If you don't know this club, simply reject the invitation or ignore this email.</p>
    </div>` }).html,
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
app.post("/business/team", requireAuth, requireClub("owner", "manager"), omeji({ kljuc: "ekipa", najvec: 30, oknoSekund: 3600, poUporabniku: true }), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const b = req.body || {};
    const email = typeof b.email === "string" ? b.email.trim().toLowerCase() : "";
    const role = typeof b.role === "string" ? b.role.trim().toLowerCase() : "";
    if (!email || !email.includes("@")) return res.status(400).send("Valid email is required.");
    if (!VLOGE_EKIPE.includes(role)) return res.status(400).send("role must be manager, doorman or bartender.");
    if (req.klub.role === "manager" && !VLOGE_OSEBJE.includes(role)) {
      return res.status(403).send("Only the club owner can invite managers.");
    }

    const u = await pool.query("SELECT id, username, email FROM users WHERE LOWER(email)=$1", [email]);
    if (u.rows.length === 0) {
      return res.status(404).json({ error: "no_account", message: "No Outly account with this email. Ask them to sign up first." });
    }
    const clan = u.rows[0];
    if (Number(clan.id) === Number(req.user.userId)) return res.status(400).send("You are already in this team.");
    // Blok (041) v obe smeri: vabila v ekipo ne prejme, kdor je blokiral vabitelja (ali ga je vabitelj blokiral); odgovor kot za neznan e-naslov.
    if (await jeBlokiran(pool, req.user.userId, clan.id)) {
      return res.status(404).json({ error: "no_account", message: "No Outly account with this email. Ask them to sign up first." });
    }

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

    // Avtoritativna preverba bloka (041) pod zaklepom para, v isti transakciji kot vpis vabila: blokiranje in vabilo se vrstita
    // (zaklep para pred zaklepi vrstic, kot povsod); zgornja preverba samo prihrani transakcijo.
    const cv = await pool.connect();
    try {
      await cv.query("BEGIN");
      await zakleniPar(cv, req.user.userId, clan.id);
      if (await jeBlokiran(cv, req.user.userId, clan.id)) {
        await cv.query("ROLLBACK");
        return res.status(404).json({ error: "no_account", message: "No Outly account with this email. Ask them to sign up first." });
      }
      await cv.query(
        "INSERT INTO club_invites (club_id, user_id, role, invited_by_user_id) VALUES ($1,$2,$3,$4)",
        [klub, clan.id, role, req.user.userId]
      );
      await cv.query("COMMIT");
    } catch (e) {
      await cv.query("ROLLBACK").catch(() => {});
      throw e;
    } finally { cv.release(); }
    const ime = await pool.query("SELECT name FROM clubs WHERE id=$1", [klub]);
    posljiVabiloEkipi(clan.email, ime.rows[0] ? ime.rows[0].name : "A club", role); // brez await: mail ne sme zadrževati odgovora
    return res.status(201).json(await odgovorEkipe(req, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /business/team/invites/:id — prekliče čakajoče vabilo. Manager sme samo vratarje in natakarje.
// (Definirano PRED /business/team/:userId; poti se ne prekrivata, ker ima ta dodaten del.)
app.delete("/business/team/invites/:id", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid invite id.");
    const i = await pool.query("SELECT role FROM club_invites WHERE id=$1 AND club_id=$2 AND status='pending'", [id, klub]);
    if (i.rows.length === 0) return res.status(404).send("Invitation not found.");
    if (req.klub.role === "manager" && !VLOGE_OSEBJE.includes(i.rows[0].role)) {
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

// Blok med dvema uporabnikoma (041): velja v OBE smeri, blokirani ne izve (odgovor je enak kot za neobstojecega uporabnika).
// zakleniPar vrsti vse, kar vzpostavlja ali preverja odnos para (blokiranje, prosnja za prijateljstvo, sprejem, prenos vstopnice, vabilo na guest listo):
// brez zaklepa bi prosnja, ki je ze prebrala »ni bloka«, lahko zapisala prijateljstvo tik po commitu bloka. Kljuc je neodvisen od smeri (manjsi:vecji id).
// Zaklep se vzame PRED zaklepi vrstic friend_requests/friendships (isti vrstni red povsod: brez zastoja).
async function zakleniPar(db, a, b) {
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`blok-par:${Math.min(Number(a), Number(b))}:${Math.max(Number(a), Number(b))}`]);
}
async function jeBlokiran(db, a, b) {
  const r = await db.query(
    "SELECT 1 FROM user_blocks WHERE (blocker_id = $1::int AND blocked_id = $2::int) OR (blocker_id = $2::int AND blocked_id = $1::int) LIMIT 1", [a, b]
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
          AND NOT EXISTS (SELECT 1 FROM user_blocks b WHERE (b.blocker_id = u.id AND b.blocked_id = $2::int) OR (b.blocker_id = $2::int AND b.blocked_id = u.id))   -- blok (041) velja v obe smeri
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
      // Blok (041) v obe smeri: kot da uporabnik ne obstaja (isti odgovor kot za neznano ime). Pod zaklepom para: blokiranje in prosnja se vrstita.
      await zakleniPar(client, req.user.userId, cilj.id);
      if (await jeBlokiran(client, req.user.userId, cilj.id)) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "no_account", message: "No Outly account with this username." });
      }
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
    // Blok (041): najprej zaklep para (posiljatelja preberemo brez zaklepa vrstice), sele nato zaklep vrstice; blokiranje prosnjo ze preklice.
    const pred = await client.query("SELECT from_user_id FROM friend_requests WHERE id = $1 AND to_user_id = $2 AND status = 'pending'", [id, req.user.userId]);
    if (pred.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).send("Request not found or no longer pending."); }
    await zakleniPar(client, req.user.userId, pred.rows[0].from_user_id);
    const r = await client.query(
      `SELECT r.id, r.from_user_id, ${POLJA_PRIJATELJA} FROM friend_requests r JOIN users u ON u.id = r.from_user_id
        WHERE r.id = $1 AND r.to_user_id = $2 AND r.status = 'pending' FOR UPDATE OF r`, [id, req.user.userId]
    );
    if (r.rows.length === 0 || await jeBlokiran(client, req.user.userId, r.rows[0].from_user_id)) { await client.query("ROLLBACK"); return res.status(404).send("Request not found or no longer pending."); }
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

// ---------------------------
// PRIJAVE ZLORABE IN BLOKI (migracija 041, issue #189, Apple App Review 1.2 »uporabniska vsebina«)
// ---------------------------
// POST /reports: vsak prijavljen uporabnik prijavi uporabnika, klub, dogodek ali sliko kluba (media: target_id = id kluba). Admin prijave pregleda
// v admin panelu (GET/PATCH /admin/api/reports) in dobi mail, ce je nastavljen ADMIN_PRIJAVE_EMAIL. Blokiranje je tiho: blokirani ne izve, blok
// velja v obe smeri (iskanje, prosnja za prijateljstvo, prenos vstopnice, vabilo na guest listo, vabilo v ekipo), prijateljstvo in cakajoce prosnje
// ob blokiranju izginejo in se ob odblokiranju NE obnovijo. Napake: { error: "koda", message }.
const PRIJAVA_CILJI = ["user", "club", "event", "media"];
const PRIJAVA_VZROKI = ["spam", "harassment", "inappropriate", "impersonation", "illegal", "other"];
const PRIJAVA_DETAJLI_NAJVEC = 1000;
const PRIJAVE_NA_DAN = okoljeCelo("PRIJAVE_NA_DAN", 50, 1, 1000);                 // najvec prijav enega uporabnika v 24 h (zloraba prijav = poplava admina)
const PRIJAVE_MAIL_NA_URO = okoljeCelo("PRIJAVE_MAIL_NA_URO", 10, 0, 1000);       // najvec mailov adminu na uro na proces (0 = nikoli); ostale prijave so v panelu
const BLOKOV_NAJVEC = okoljeCelo("BLOKI_NAJVEC", 500, 1, 100000);                 // najvec blokov enega uporabnika

// Cilj prijave: obstaja in je javen (uporabnik ni racun za kopije; klub ni skrit; dogodek je objavljen in klub ni skrit). Vrne { label } ali null.
async function najdiCiljPrijave(db, tip, id) {
  let r;
  if (tip === "user") r = await db.query("SELECT username AS label FROM users WHERE id = $1 AND role <> 'backup'", [id]);
  else if (tip === "club" || tip === "media") r = await db.query("SELECT name AS label FROM clubs WHERE id = $1 AND NOT hidden", [id]);
  else r = await db.query(
    "SELECT e.title || ' (' || c.name || ')' AS label FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1 AND e.status = 'published' AND NOT c.hidden", [id]);
  return r.rows[0] || null;
}

// Mail adminu ob novi prijavi: samo ce je ADMIN_PRIJAVE_EMAIL (naslovi z vejico) IN Resend nastavljen. Klic je brez await po commitu in odgovoru:
// napaka ali pocasen Resend ne podre ne upocasni prijave (gostResendPosli ima rok in vrne { error }, ne vrze). V mailu je od prijavitelja samo
// uporabnisko ime; besedila `details` (prosto besedilo prijavitelja) ni, admin ga vidi v panelu.
let prijavaMailOkno = { od: 0, n: 0 };
function posljiMailPrijave(p) {
  const naslovi = String(process.env.ADMIN_PRIJAVE_EMAIL || "").split(",").map(e => e.trim()).filter(Boolean);
  if (!naslovi.length || !resend) return;
  const zdaj = Date.now();
  if (zdaj - prijavaMailOkno.od >= 3600 * 1000) prijavaMailOkno = { od: zdaj, n: 0 };
  if (prijavaMailOkno.n >= PRIJAVE_MAIL_NA_URO) { console.log(`[prijave] mail za prijavo ${p.id} preskocen (meja ${PRIJAVE_MAIL_NA_URO} na uro); prijava je v admin panelu`); return; }
  prijavaMailOkno.n++;
  const appName = process.env.APP_NAME || "Outly";
  const vrstica = (k, v) => `<tr><td style="padding:4px 12px 4px 0;color:#666">${k}</td><td style="padding:4px 0"><b>${ubeziHtml(v)}</b></td></tr>`;
  void (async () => {
    try {
      const r = await gostResendPosli({
        to: naslovi,
        subject: `Nova prijava zlorabe #${p.id} (${p.tip})`,
        html: `<div style="font-family: Arial, sans-serif; line-height:1.5"><h2>${ubeziHtml(appName)} – nova prijava zlorabe (#${p.id})</h2>
      <table>${vrstica("Vrsta cilja", p.tip)}${vrstica("Cilj", p.label)}${vrstica("Razlog", p.vzrok)}${vrstica("Prijavil", p.prijavitelj || "-")}</table>
      <p>Pregled in razresitev: <a href="https://outly-backend-roy3.onrender.com/admin/">outly-backend-roy3.onrender.com/admin</a> → Reports.</p></div>`,
        text: `${appName}: nova prijava zlorabe #${p.id}\nVrsta cilja: ${p.tip}\nCilj: ${p.label}\nRazlog: ${p.vzrok}\nPrijavil: ${p.prijavitelj || "-"}\nPregled: https://outly-backend-roy3.onrender.com/admin/ (zavihek Reports)`,
      });
      if (r && r.error) console.error("Resend napaka (prijava zlorabe):", JSON.stringify(r.error));
    } catch (e) { console.error("Resend napaka (prijava zlorabe):", e && (e.message || String(e))); }
  })();
}

// POST /reports { target_type, target_id, reason, details? } -> 201 { ok: true, id }; ista prijava istega cilja istega uporabnika v 24 h -> 200 { ok: true, id }
// (brez podvajanja). 400 invalid_target_type | invalid_reason | invalid_target | invalid_details, 404 not_found, 429 (omejevalnik ali too_many_reports).
app.post("/reports", requireAuth, omeji({ kljuc: "prijava", najvec: 20, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
  if (typeof b.target_type !== "string" || !PRIJAVA_CILJI.includes(b.target_type)) {
    return res.status(400).json({ error: "invalid_target_type", message: `target_type must be one of: ${PRIJAVA_CILJI.join(", ")}.` });
  }
  if (typeof b.reason !== "string" || !PRIJAVA_VZROKI.includes(b.reason)) {
    return res.status(400).json({ error: "invalid_reason", message: `reason must be one of: ${PRIJAVA_VZROKI.join(", ")}.` });
  }
  const ciljId = Number.isInteger(b.target_id) && b.target_id > 0 ? b.target_id : (typeof b.target_id === "string" ? celoId4(b.target_id) : null);
  if (!ciljId || ciljId > INT4_MAX) return res.status(400).json({ error: "invalid_target", message: "target_id must be a positive integer id." });
  let podrobnosti = null;
  if (b.details !== undefined && b.details !== null) {
    if (typeof b.details !== "string") return res.status(400).json({ error: "invalid_details", message: "details must be text." });
    podrobnosti = b.details.replace(/\u0000/g, "").trim() || null;   // NUL baza zavrne (500); prazno besedilo = brez podrobnosti
    if (podrobnosti && Array.from(podrobnosti).length > PRIJAVA_DETAJLI_NAJVEC) {
      return res.status(400).json({ error: "invalid_details", message: `details can be at most ${PRIJAVA_DETAJLI_NAJVEC} characters.` });
    }
  }
  const userId = req.user.userId;
  if (b.target_type === "user" && ciljId === Number(userId)) return res.status(400).json({ error: "invalid_target", message: "You can't report yourself." });

  const c = await pool.connect();
  try {
    await nakupZacni(c);
    // Prijave istega uporabnika se vrstijo (podvojena prijava in dnevna meja ne smeta pasti pri socasnih zahtevkih).
    await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`prijava:${userId}`]);
    const cilj = await najdiCiljPrijave(c, b.target_type, ciljId);
    if (!cilj) { await c.query("ROLLBACK"); return res.status(404).json({ error: "not_found", message: "Nothing to report here." }); }
    const ze = await c.query(
      `SELECT id FROM reports WHERE reporter_id = $1 AND target_type = $2 AND target_id = $3 AND created_at > NOW() - INTERVAL '24 hours' ORDER BY id DESC LIMIT 1`,
      [userId, b.target_type, ciljId]);
    if (ze.rows.length) { await c.query("ROLLBACK"); return res.status(200).json({ ok: true, id: ze.rows[0].id }); }
    const dan = (await c.query("SELECT COUNT(*)::int AS n FROM reports WHERE reporter_id = $1 AND created_at > NOW() - INTERVAL '24 hours'", [userId])).rows[0].n;
    if (dan >= PRIJAVE_NA_DAN) {
      await c.query("ROLLBACK");
      res.set("Retry-After", "3600");
      return res.status(429).json({ error: "too_many_reports", message: "Too many reports today. Please try again later." });
    }
    const ins = await c.query(
      "INSERT INTO reports (reporter_id, target_type, target_id, reason, details) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [userId, b.target_type, ciljId, b.reason, podrobnosti]);
    await c.query("COMMIT");
    const id = ins.rows[0].id;
    res.status(201).json({ ok: true, id });
    console.log(`[prijave] nova prijava ${id}: ${b.target_type} ${ciljId}, razlog ${b.reason}`);
    posljiMailPrijave({ id, tip: b.target_type, label: cilj.label, vzrok: b.reason, prijavitelj: req.user.username });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (napakaZasedenosti(e)) { console.error(e.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    return odgovoriNaNapako(res, e, "POST /reports");
  } finally { c.release(); }
});

// POST /me/blocks/:userId -> 204 (idempotentno). Prijateljstvo (obe smeri) in cakajoce prosnje med njima izginejo; 400 invalid_target (sebe / neveljaven id),
// 404 not_found (uporabnik ne obstaja), 409 blocks_limit.
app.post("/me/blocks/:userId", requireAuth, omeji({ kljuc: "bloki", najvec: 60, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  const uid = celoId4(req.params.userId);
  const jaz = Number(req.user.userId);
  if (!uid || uid === jaz) return res.status(400).json({ error: "invalid_target", message: "You can't block yourself." });
  const c = await pool.connect();
  try {
    await nakupZacni(c);
    await zakleniPar(c, jaz, uid);
    const t = await c.query("SELECT 1 FROM users WHERE id = $1 AND role <> 'backup'", [uid]);
    if (!t.rows.length) { await c.query("ROLLBACK"); return res.status(404).json({ error: "not_found", message: "User not found." }); }
    const ze = await c.query("SELECT 1 FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2", [jaz, uid]);
    if (!ze.rows.length) {
      const st = (await c.query("SELECT COUNT(*)::int AS n FROM user_blocks WHERE blocker_id = $1", [jaz])).rows[0].n;
      if (st >= BLOKOV_NAJVEC) { await c.query("ROLLBACK"); return res.status(409).json({ error: "blocks_limit", message: "You have reached the limit of blocked users." }); }
      await c.query("INSERT INTO user_blocks (blocker_id, blocked_id) VALUES ($1, $2)", [jaz, uid]);
    }
    // Tudi ob ponovnem blokiranju (idempotentno) se ostanki odnosa pospravijo.
    await c.query("DELETE FROM friendships WHERE user_a = LEAST($1::int, $2::int) AND user_b = GREATEST($1::int, $2::int)", [jaz, uid]);
    await c.query(
      `UPDATE friend_requests SET status = 'cancelled', responded_at = NOW()
        WHERE status = 'pending' AND LEAST(from_user_id, to_user_id) = LEAST($1::int, $2::int) AND GREATEST(from_user_id, to_user_id) = GREATEST($1::int, $2::int)`, [jaz, uid]);
    await c.query("COMMIT");
    return res.status(204).send();
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (e && e.code === "23503") return res.status(404).json({ error: "not_found", message: "User not found." });   // uporabnik izbrisan med preverbo in vpisom
    if (napakaZasedenosti(e)) { console.error(e.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    return odgovoriNaNapako(res, e, "POST /me/blocks/:userId");
  } finally { c.release(); }
});

// DELETE /me/blocks/:userId -> 204 (idempotentno; tudi ce bloka ni). Prijateljstvo se NE obnovi.
app.delete("/me/blocks/:userId", requireAuth, omeji({ kljuc: "bloki", najvec: 60, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  try {
    const uid = celoId4(req.params.userId);
    if (!uid) return res.status(400).json({ error: "invalid_target", message: "Invalid user id." });
    await pool.query("DELETE FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2", [req.user.userId, uid]);
    return res.status(204).send();
  } catch (e) { return odgovoriNaNapako(res, e, "DELETE /me/blocks/:userId"); }
});

// GET /me/blocks -> { blocks: [{ user_id, username, avatar_url, blocked_at }] } (samo koga sem blokiral jaz; kdo je blokiral mene se ne razkrije).
app.get("/me/blocks", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.id AS user_id, u.username, u.avatar_url, b.created_at AS blocked_at
         FROM user_blocks b JOIN users u ON u.id = b.blocked_id
        WHERE b.blocker_id = $1 ORDER BY b.created_at DESC, u.id LIMIT 1000`, [req.user.userId]);
    return res.json({ blocks: r.rows });
  } catch (e) { return odgovoriNaNapako(res, e, "GET /me/blocks"); }
});

// --- admin: prijave zlorabe (migracija 041; vloga admin prek routerja `admin`) ---
// Oblika vrstice: id, reporter_username (null = racun prijavitelja je izbrisan), target_type, target_id, target_label (null = cilj ne obstaja vec),
// reason, details, created_at, status, resolved_at, note.
const PRIJAVE_ADMIN_SQL = `
  SELECT r.id, ru.username AS reporter_username, r.target_type, r.target_id,
         CASE r.target_type
           WHEN 'user'  THEN (SELECT x.username FROM users x WHERE x.id = r.target_id)
           WHEN 'club'  THEN (SELECT x.name FROM clubs x WHERE x.id = r.target_id)
           WHEN 'media' THEN (SELECT x.name FROM clubs x WHERE x.id = r.target_id)
           WHEN 'event' THEN (SELECT x.title || ' (' || c.name || ')' FROM events x JOIN clubs c ON c.id = x.club_id WHERE x.id = r.target_id)
         END AS target_label,
         r.reason, r.details, r.created_at, r.status, r.resolved_at, r.note
    FROM reports r LEFT JOIN users ru ON ru.id = r.reporter_id`;

// GET /admin/api/reports?status=open|resolved|all (privzeto open) -> { reports: [...] } najnovejse prve, najvec 500.
admin.get("/reports", async (req, res) => {
  try {
    const status = req.query.status === undefined ? "open" : String(req.query.status);
    if (!["open", "resolved", "all"].includes(status)) return res.status(400).json({ error: "invalid_status", message: "status must be open, resolved or all." });
    const r = await pool.query(`${PRIJAVE_ADMIN_SQL} WHERE ($1::text = 'all' OR r.status = $1::text) ORDER BY r.created_at DESC, r.id DESC LIMIT 500`, [status]);
    return res.json({ reports: r.rows });
  } catch (e) { return odgovoriNaNapako(res, e, "GET /admin/api/reports"); }
});

// GET /admin/api/help-feedback -> { articles: [{ article, helpful, not_helpful, last_at }] } po stevilu glasov padajoce (nato po id-ju). SAMO agregati: brez uporabnikov in e-naslovov.
// Stevci so cela stevila (COUNT je BIGINT -> ::int), last_at = cas zadnjega glasu (updated_at).
admin.get("/help-feedback", async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT article,
              COUNT(*) FILTER (WHERE helpful)::int     AS helpful,
              COUNT(*) FILTER (WHERE NOT helpful)::int AS not_helpful,
              MAX(updated_at)                          AS last_at
         FROM help_feedback GROUP BY article
        ORDER BY COUNT(*) DESC, article LIMIT 1000`);
    return res.json({ articles: r.rows });
  } catch (e) { return odgovoriNaNapako(res, e, "GET /admin/api/help-feedback"); }
});

// PATCH /admin/api/reports/:id { status: "resolved" | "open", note? } -> { report }. note: niz do 1000 znakov; null ali "" ga zbrise; brez polja ostane.
admin.patch("/reports/:id", async (req, res) => {
  try {
    const id = celoId4(req.params.id);
    if (!id) return res.status(400).json({ error: "invalid_id", message: "Invalid report id." });
    const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
    if (b.status !== "resolved" && b.status !== "open") return res.status(400).json({ error: "invalid_status", message: "status must be resolved or open." });
    let spremeniOpombo = false, opomba = null;
    if (b.note !== undefined) {
      if (b.note !== null && typeof b.note !== "string") return res.status(400).json({ error: "invalid_note", message: "note must be text." });
      opomba = typeof b.note === "string" ? (b.note.replace(/\u0000/g, "").trim() || null) : null;
      if (opomba && Array.from(opomba).length > 1000) return res.status(400).json({ error: "invalid_note", message: "note can be at most 1000 characters." });
      spremeniOpombo = true;
    }
    const u = await pool.query(
      `UPDATE reports SET status = $2::text,
              note = CASE WHEN $3::boolean THEN $4::text ELSE note END,
              resolved_at = CASE WHEN $2::text = 'resolved' THEN COALESCE(resolved_at, NOW()) ELSE NULL END,
              resolved_by = CASE WHEN $2::text = 'resolved' THEN COALESCE(resolved_by, $5::int) ELSE NULL END
        WHERE id = $1 RETURNING id`, [id, b.status, spremeniOpombo, opomba, req.user.userId]);
    if (!u.rows.length) return res.status(404).json({ error: "not_found", message: "Report not found." });
    const r = await pool.query(`${PRIJAVE_ADMIN_SQL} WHERE r.id = $1`, [id]);
    console.log(`[prijave] admin ${req.user.userId}: prijava ${id} -> ${b.status}`);
    return res.json({ report: r.rows[0] });
  } catch (e) { return odgovoriNaNapako(res, e, "PATCH /admin/api/reports/:id"); }
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

// DELETE /business/team/:userId — odstrani člana. Manager sme samo vratarje in natakarje.
app.delete("/business/team/:userId", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const uid = celoId(req.params.userId);
    if (!uid) return res.status(400).send("Invalid user id.");
    const m = await pool.query("SELECT role FROM club_members WHERE club_id=$1 AND user_id=$2", [klub, uid]);
    if (m.rows.length === 0) return res.status(404).send("Member not found.");
    if (req.klub.role === "manager" && !VLOGE_OSEBJE.includes(m.rows[0].role) && Number(uid) !== Number(req.user.userId)) {
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
// Casovne meje povezav (#139, korak 2): keepAliveTimeout nad mirovalnim rokom Renderjevega proxyja (KEEPALIVE_MS, privzeto 120000),
// headersTimeout = keepAlive + 1 s. Brez tega Node po 5 s zapre vzdrzevano povezavo, ki jo proxy se uporablja.
const meje = require("./nastavitve_povezav").nastaviMejePovezav(streznik, process.env.KEEPALIVE_MS);
console.log(`[meje-povezav] keepAliveTimeout ${meje.keepAliveMs} ms, headersTimeout ${meje.headersMs} ms, requestTimeout ${meje.requestMs} ms`);
// Dnevnik povezav (#139): enkrat na DNEVNIK_POVEZAV_MS (privzeto 60000, 0 = izklop) vrstica `[povezave] ...`, samo ob prometu.
require("./dnevnik_povezav").zagoniDnevnikPovezav(streznik, stevilkaIzOkolja("DNEVNIK_POVEZAV_MS", 60000, 3600000));
