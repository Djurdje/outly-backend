// Pavza prodaje (migracija 055, invarianta I53, Martin 21. 10. 2026): ob vklopu `events.sales_paused` se odprta placilna okna dogodka prekinejo,
// da po ustavitvi nihce vec ne placa.
//
// Kako (dva koraka):
//  1. V ISTI transakciji kot `sales_paused = TRUE` (index.js, PATCH /events/:id): `prekliciCakajoca(c, eventId)` postavi cakajoca narocila dogodka
//     z odprto ali se ustvarjajoco Stripe sejo na `cancelled` (sprozilec sprosti zalogo, unikatni indeks mize jo spusti). Placila v obdelavi (odlozeno placilo:
//     seja `complete`, `checkout_url` NULL ob obstojeci seji) NE: kupec je svoj del ze opravil, denar je na poti.
//  2. PO COMMIT-u, asinhrono (`zazeni(eventId)`): Stripove seje teh narocil se zaprejo (`checkout.sessions.expire`). Povezava z bazo se med klici Stripa
//     NE drzi (seznam se prebere s kratko poizvedbo), najvec PAVZA_STRIPE_VZPOREDNO klicev hkrati, vsak do PAVZA_STRIPE_POSKUSOV poskusov z narascajocim
//     premorom; vse v dnevnik `[pavza]`. Po PAVZA_KMALU_MS (3 s) in PAVZA_PONOVNO_MS (90 s) se oba koraka ponovita: ujameta nakup mize, ki je dogodek prebral
//     TIK pred pavzo in se commital med njo (nakup mize vrstice dogodka ne zaklene; nakup vstopnic pocaka na zaklep v sprozilcu rezerviraj_zalogo in ga
//     nakupStripeSeja zavrne), ter sejo, ki je bila ob prvem koraku sele v nastajanju. Preostalo okno (I53): nakup mize, ki je sejo zapisal pred COMMIT-om
//     pavze, ima do naslednjega koraka (najvec ~3 s, ob pocasnem Stripu do 90 s) odprto placilno okno.
//
// Dirka (placilo pride kljub temu, npr. kupec potrdi placilo v istem trenutku): narocilo je ze `cancelled`, zato zakljuci() v placila_stripe.js placila
// NE vknjizi in kupcu vrne vse (`inactive_order`, I37). Ni placila brez vstopnice (vracilo) in ni vstopnice brez narocila (vstopnice nastanejo samo v zakljuci()).
// Sken vstopnic se tega ne dotika (I16): nic ne tece na skenPool, vstopnice se ne zaklepajo.

const okoljeSt = (ime, privzeto, min, max) => {
  const v = Number(process.env[ime]);
  return Number.isFinite(v) && v >= min && v <= max ? Math.floor(v) : privzeto;
};

// Cakajoca narocila dogodka, katerih placilno okno je odprto ali se odpira (seja se ustvarja: stripe_checkout_session_id NULL).
// Placilo v obdelavi = seja obstaja, checkout_url NULL (placila_stripe.js oznaciVObdelavi) -> izvzeto.
const POGOJ_ODPRTEGA_OKNA = `status = 'pending' AND (checkout_url IS NOT NULL OR stripe_checkout_session_id IS NULL)`;

// Korak 1 (v transakciji klicatelja). Vrne stevilo preklicanih narocil. `samoCePavza`: preklici samo, ce je dogodek se vedno ustavljen
// (ponovni korak po zamiku ne sme preklicati nakupov, ce je admin prodajo medtem spet vklopil).
async function prekliciCakajoca(c, eventId, { samoCePavza = false } = {}) {
  const r = await c.query(
    `UPDATE orders SET status = 'cancelled', cancelled_at = NOW()
      WHERE event_id = $1 AND ${POGOJ_ODPRTEGA_OKNA}
        ${samoCePavza ? "AND EXISTS (SELECT 1 FROM events e WHERE e.id = $1 AND e.sales_paused)" : ""}
      RETURNING id`, [eventId]);
  return r.rows.length;
}

function ustvari({ pool, stripe, jeLive, razprodanoPozabi }) {
  const VZPOREDNO = okoljeSt("PAVZA_STRIPE_VZPOREDNO", 4, 1, 20);
  const POSKUSOV = okoljeSt("PAVZA_STRIPE_POSKUSOV", 4, 1, 10);
  const PREMOR_MS = okoljeSt("PAVZA_STRIPE_PREMOR_MS", 1000, 0, 60000);
  const PONOVNO_MS = okoljeSt("PAVZA_PONOVNO_MS", 90000, 0, 600000);
  const KMALU_MS = okoljeSt("PAVZA_KMALU_MS", 3000, 0, 60000);
  const zaprte = new Map();   // eventId -> Set(id seje), da drugi korak iste seje ne zapira znova (samo v procesu; ponovni expire bi bil le odvecen klic)
  const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms).unref?.());

  // Trajna napaka Stripa (seja ni vec odprta, ne obstaja, napacen nacin): ne ponavljamo. Omrezje, 429, 5xx: ponovimo.
  const trajna = (e) => !!e && (e.type === "StripeInvalidRequestError" || e.statusCode === 400 || e.statusCode === 404);

  async function zapri(s, eventId, sejaId) {
    for (let poskus = 1; poskus <= POSKUSOV; poskus++) {
      try {
        await s.checkout.sessions.expire(sejaId);
        console.log(`[pavza] dogodek ${eventId}: placilno okno ${sejaId} zaprto`);
        return "zaprto";
      } catch (e) {
        if (trajna(e)) {
          // Najpogosteje: seja je ze potekla ali je bila placana tik pred tem (tedaj zakljuci() narocilo, ki je `cancelled`, vrne kupcu: inactive_order).
          console.log(`[pavza] dogodek ${eventId}: seje ${sejaId} ni bilo treba zapreti (${e.message || e})`);
          return "ni_odprta";
        }
        if (poskus === POSKUSOV) {
          console.error(`[pavza] POZOR: dogodek ${eventId}: placilnega okna ${sejaId} ni bilo mogoce zapreti po ${POSKUSOV} poskusih (${e.message || e}). ` +
            "Naroclilo je preklicano: ce kupec vseeno placa, mu zakljuci() vrne denar (inactive_order).");
          return "napaka";
        }
        await pocakaj(PREMOR_MS * 2 ** (poskus - 1));
      }
    }
    return "napaka";
  }

  // Seje preklicanih narocil dogodka (od trenutka pavze `od`), ki jih se nismo zaprli. Kratka poizvedba, povezava se ne drzi.
  async function zapriSeje(eventId, od) {
    const s = stripe();
    if (!s) return { zaprto: 0, skupaj: 0 };
    const r = await pool.query(
      `SELECT stripe_checkout_session_id AS seja FROM orders
        WHERE event_id = $1 AND status = 'cancelled' AND cancelled_at >= $2 AND stripe_checkout_session_id IS NOT NULL AND stripe_payment_intent_id IS NULL`,
      [eventId, od]);
    const ze = zaprte.get(eventId) || new Set();
    zaprte.set(eventId, ze);
    const seje = r.rows.map((x) => x.seja).filter((id) => !ze.has(id) && !(jeLive() && /^cs_test_/.test(id)));   // sandbox seje ob zivem kljucu Stripe ne pozna (I36)
    let i = 0, zaprto = 0;
    const delavec = async () => {
      while (i < seje.length) {
        const id = seje[i++];
        const izid = await zapri(s, eventId, id);
        if (izid !== "napaka") ze.add(id);
        if (izid === "zaprto") zaprto++;
      }
    };
    await Promise.all(Array.from({ length: Math.min(VZPOREDNO, seje.length) }, delavec));
    return { zaprto, skupaj: seje.length };
  }

  // Korak 2 (po COMMIT-u, brez await pri klicatelju). `od` = cas pavze (NOW() transakcije), da ne zapiramo sej starih preklicev.
  function zazeni(eventId, od) {
    const tek = async (drugic) => {
      try {
        if (drugic) {
          const c = await pool.connect();
          let n = 0;
          try {
            await c.query("BEGIN");
            n = await prekliciCakajoca(c, eventId, { samoCePavza: true });
            await c.query("COMMIT");
          } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
          finally { c.release(); }
          if (n > 0) { console.log(`[pavza] dogodek ${eventId}: ponovni korak je preklical se ${n} cakajocih narocil (nakup tik pred pavzo)`); if (razprodanoPozabi) razprodanoPozabi(eventId); }
        }
        const { zaprto, skupaj } = await zapriSeje(eventId, od);
        if (skupaj > 0 || !drugic) console.log(`[pavza] dogodek ${eventId}: ${drugic ? "ponovni korak" : "prvi korak"}, zaprtih placilnih oken ${zaprto} od ${skupaj}`);
      } catch (e) {
        console.error(`[pavza] POZOR: dogodek ${eventId}: prekinitev placilnih oken ni uspela (${e && e.message}); pospravljalec in zakljuci() ujameta preostanek.`);
      }
    };
    const prvi = tek(false);
    // Dva ponovna koraka: kmalu (nakup mize, ki je dogodek prebral pred pavzo in se commital med njo; seja se se ustvarja) in po PONOVNO_MS
    // (pocasen Stripe: ustvarjanje seje traja do ~45 s). Ponovni koraka nista vzporedna s prvim (zaporedno v eni verigi).
    let veriga = prvi;
    for (const ms of [Math.min(KMALU_MS, PONOVNO_MS), PONOVNO_MS]) {
      const t = setTimeout(() => { veriga = veriga.then(() => tek(true)); if (ms === PONOVNO_MS) veriga.finally(() => zaprte.delete(eventId)); }, ms);
      if (t.unref) t.unref();
    }
    return prvi;
  }

  return { zazeni, zapriSeje };
}

module.exports = { ustvari, prekliciCakajoca, POGOJ_ODPRTEGA_OKNA };
