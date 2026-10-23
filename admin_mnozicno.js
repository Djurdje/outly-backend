// Mnozicna dejanja nad dogodki v admin panelu (#329, nacrt outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md 2.4, invarianta I60).
//
// POST /admin/api/events/bulk { ids: [<= 50], dejanje, razlog, zamik_min? } (samo vloga admin, router `admin` v index.js).
//   dejanje: pause | resume | draft | reschedule. »cancel« in »delete« NISTA mogoca (vracila denarja ostanejo posamicna, z vpisom ODPOVEJ) -> 400.
// Odgovor 200: { dejanje, results: [{ id, ok, spremenjeno?, napaka?, status?, message?, potem? }] } po dogodkih v vrstnem redu ids (brez podvojenih).
//
// NI nova logika, samo zanka nad obstojecimi potmi (ponovna raba, ne kopija):
//   pause / resume -> urediDogodek({ salesPaused }) = isto kot stikalo »Prodaja tece« (I53: preklic cakajocih narocil v ISTI transakciji, zaklep 73112,
//                      zapiranje Stripovih sej v ozadju po COMMIT-u z mejami PAVZA_STRIPE_* in procesno mejo PAVZA_STRIPE_SKUPAJ, pavza_prodaje.js);
//   draft          -> adminStatusDogodka({ status: "draft" }) = »Med osnutke« (placane vstopnice ostanejo veljavne; odpovedan dogodek 409 event_cancelled);
//   reschedule     -> urediDogodek({ startAt, endAt, salesOpenAt, salesCloseAt }) = ista validacija kot PATCH, a SAMO dogodek brez prodaje (spodaj).
// Vsak dogodek ima SVOJO transakcijo (napaka enega ne ustavi ostalih), dogodki tecejo ZAPOREDNO (en dogodek = najvec ena povezava iz glavnega poola; 50 vzporednih bi
// zasedlo pool, ki ga rabijo nakupi). Vsaka sprememba = ena vrstica admin_dejanja z istim `razlog` (v ISTI transakciji kot sprememba, kot pri posamicnem PATCH).
// Nic na skenPool; zaklep samo vrstice dogodka (FOR NO KEY UPDATE, kot PATCH), sken vrstice dogodka ne zaklepa (I16).
//
// reschedule: premik za `zamik_min` minut (celo, != 0, najvec +-30 dni). Zacetek se premakne po LJUBLJANSKI uri (ura ostane ista tudi cez prehod poletnega casa, kot
// podvajanje), konec in okno prodaje (sales_open_at / sales_close_at, ce sta nastavljena) za ISTI absolutni zamik: trajanje in zamik okna od zacetka ostaneta.
// 409 `has_sales`: dogodek ima placana ali delno vracena narocila, narocilo v teku (pending) ali veljavno/unovceno vstopnico (tudi guest lista in VIP miza, ker gredo
// vse prek orders/tickets). Preverba je v transakciji POD zaklepom vrstice: nakup, ki je ze vstavil narocilo (sprozilec rezerviraj_zalogo drzi vrstico dogodka do COMMIT-a), prestavitev ustavi (has_sales). PREOSTALO OKNO (priznano, I60): nakup, ki je dogodek PREBRAL pred prestavitvijo in narocilo vstavi sele po njenem COMMIT-u (caka v sprozilcu), se zakljuci s starim prikazom datuma; vstopnica velja za dogodek s NOVIM datumom. Izkljucni advisory 73112 tega ne zapre (nakup ga vzame deljenega sele tik pred COMMIT-om, po vstavitvi), zapiranje bi zahtevalo primerjavo start_at v vseh nakupnih poteh (obcutljivo, I53/I2). Zato pavza (pause) pred prestavitvijo in prestavitev izven konice prodaje. Pravno odprto: #259
// (obvestilo kupcem), I42. 409 `event_finished`: dogodek se je ze zacel. 400 `start_in_past`: nov zacetek ni v prihodnosti. 409 `event_cancelled`: odpovedan dogodek.
const { NEVIDNI } = require("./agent_predlogi");

const IDOV_NAJVEC = 50;
const ZAMIK_NAJVEC_MIN = 30 * 1440;
const DEJANJA = new Set(["pause", "resume", "draft", "reschedule"]);
const PREPOVEDANA = new Set(["cancel", "delete"]);
const RAZLOG_MIN = 3, RAZLOG_NAJVEC = 500;
// Dogodek, ki ga drugje drzi zaklep vrstice (ali advisory zaklep pavze), ne sme zadrzati celega klica: SET LOCAL lock_timeout (privzeto 3 s) -> 55P03 -> per-dogodek 503 `event_busy`
// (nic spremenjeno, ponovi). Glavni pool lock_timeout nima. Skupni proracun klica (privzeto 60 s, pod rokom Renderja): ko poteče, preostali dogodki dobijo `not_processed` (nic spremenjeno).
const okoljeMs = (ime, privzeto) => { const n = Number(process.env[ime]); return Number.isFinite(n) && n >= 1 && n <= 600000 ? Math.floor(n) : privzeto; };
const ZAKLEP_MS = okoljeMs("ADMIN_MNOZICNO_ZAKLEP_MS", 3000), PRORACUN_MS = okoljeMs("ADMIN_MNOZICNO_PRORACUN_MS", 60000);
const predZaklepom = async (c) => { await c.query(`SET LOCAL lock_timeout = ${ZAKLEP_MS}`); };

function ustvari({ pool, urediDogodek, adminStatusDogodka, celoId4 }) {
  const napaka = (res, status, error, message) => res.status(status).json({ error, message });

  // Lazni odgovor za obstojece obdelovalce (urediDogodek, adminStatusDogodka pisejo v `res`): zajame status in telo.
  function zajemi() {
    const o = { status: 200, telo: undefined };
    const res = { status(s) { o.status = s; return res; }, json(b) { o.telo = b; return res; }, send(b) { o.telo = b; return res; }, set() { return res; }, o };
    return res;
  }
  // Napaka obstojece poti -> { napaka: koda, status, message }. Navadno besedilo (400/404 iz urediDogodek) dobi kodo po statusu.
  function izNapake(o) {
    const t = o.telo;
    if (t && typeof t === "object" && typeof t.error === "string") return { napaka: t.error, status: o.status, message: String(t.message || t.error).slice(0, 300) };
    const koda = o.status === 404 ? "event_not_found" : o.status === 503 ? "event_busy" : o.status >= 500 ? "server_error" : "invalid_request";
    return { napaka: koda, status: o.status, message: String(typeof t === "string" ? t : koda).slice(0, 300) };
  }
  const NAPAKA_STREZNIK = { napaka: "server_error", status: 500, message: "Server error." };

  async function prestavi(req, id, zamikMin, razlog) {
    const st = (await pool.query(
      `SELECT status, start_at, end_at, sales_open_at, sales_close_at,
              (((start_at AT TIME ZONE 'Europe/Ljubljana') + make_interval(mins => $2::int)) AT TIME ZONE 'Europe/Ljubljana') AS nov_start,
              (start_at <= NOW()) AS zacet
         FROM events WHERE id = $1`, [id, zamikMin])).rows[0];
    if (!st) return { napaka: "event_not_found", status: 404, message: "Event not found." };
    if (st.status === "cancelled") return { napaka: "event_cancelled", status: 409, message: "The event is cancelled." };
    if (st.zacet) return { napaka: "event_finished", status: 409, message: "The event has already started, so its date can't be changed." };
    const novStart = new Date(st.nov_start), delta = novStart.getTime() - new Date(st.start_at).getTime();
    if (novStart.getTime() <= Date.now()) return { napaka: "start_in_past", status: 400, message: "The new start must be in the future." };
    const iso = (d) => new Date(new Date(d).getTime() + delta).toISOString();
    const telo = { startAt: novStart.toISOString() };
    if (st.end_at) telo.endAt = iso(st.end_at);
    if (st.sales_open_at) telo.salesOpenAt = iso(st.sales_open_at);
    if (st.sales_close_at) telo.salesCloseAt = iso(st.sales_close_at);
    const res = zajemi();
    await urediDogodek({ user: req.user, klub: req.klub, params: { id: String(id) }, body: telo }, res, {
      razlog, predZaklepom, mnozicno: true,
      // V transakciji po zaklepu vrstice: dogodek se od branja zgoraj ni spremenil in nima prodaje (zaklep vrstice zaustavi tudi nakup, ki bi ravnokar nastal).
      predlog: async (c, trenutni) => {
        const e = (await c.query(
          `SELECT e.status,
                  EXISTS (SELECT 1 FROM orders o WHERE o.event_id = e.id AND o.status IN ('paid', 'partially_refunded', 'pending')) AS narocila,
                  EXISTS (SELECT 1 FROM tickets t WHERE t.event_id = e.id AND t.status IN ('valid', 'used')) AS vstopnice
             FROM events e WHERE e.id = $1`, [id])).rows[0];
        const odgovor = (status, error, message) => { const x = new Error(error); x.odgovor = { status, telo: { error, message } }; return x; };
        const cas = (v) => (v === null || v === undefined ? null : new Date(v).getTime());
        // Vsa poslana polja (zacetek, konec, okno prodaje) morajo biti taka, kot smo jih prebrali (sicer bi prepisali tuj premik).
        const spremenjeno = [["start_at", "start_at"], ["end_at", "end_at"], ["sales_open_at", "sales_open_at"], ["sales_close_at", "sales_close_at"]]
          .some(([k]) => k in trenutni && cas(trenutni[k]) !== cas(st[k]));
        if (spremenjeno) throw odgovor(409, "event_changed", "The event was changed in the meantime. Try again.");
        if (e.status === "cancelled") throw odgovor(409, "event_cancelled", "The event is cancelled.");
        if (e.narocila || e.vstopnice) throw odgovor(409, "has_sales", "The event has paid or pending orders or tickets, so it can't be moved in bulk. Move it on its own page.");
      },
    });
    if (res.o.status !== 200) return izNapake(res.o);
    const b = res.o.telo || {};
    return { spremenjeno: true, potem: { start_at: b.start_at ? new Date(b.start_at).toISOString() : null, end_at: b.end_at ? new Date(b.end_at).toISOString() : null } };
  }

  async function eden(req, id, dejanje, razlog, zamikMin) {
    if (dejanje === "reschedule") return prestavi(req, id, zamikMin, razlog);
    const prej = (await pool.query("SELECT status, sales_paused FROM events WHERE id = $1", [id])).rows[0];
    if (!prej) return { napaka: "event_not_found", status: 404, message: "Event not found." };
    const res = zajemi();
    const sub = { user: req.user, klub: req.klub, params: { id: String(id) } };
    if (dejanje === "draft") await adminStatusDogodka({ ...sub, body: { status: "draft", reason: razlog } }, res, { brezOdpovedanih: true, predZaklepom });
    else await urediDogodek({ ...sub, body: { salesPaused: dejanje === "pause" } }, res, { razlog, predZaklepom, mnozicno: true });
    if (res.o.status !== 200) return izNapake(res.o);
    const spremenjeno = dejanje === "draft" ? prej.status !== "draft" : prej.sales_paused !== (dejanje === "pause");
    return { spremenjeno };
  }

  return async function obravnava(req, res) {
    const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
    if (!Array.isArray(b.ids) || b.ids.length === 0) return napaka(res, 400, "invalid_ids", "ids must be a non-empty array of event ids.");
    if (b.ids.length > IDOV_NAJVEC) return napaka(res, 400, "too_many", `At most ${IDOV_NAJVEC} events per request.`);
    const ids = [];
    for (const x of b.ids) {
      const id = typeof x === "number" || typeof x === "string" ? celoId4(x) : null;
      if (!id) return napaka(res, 400, "invalid_ids", "Every id must be a positive integer event id.");
      if (!ids.includes(id)) ids.push(id);
    }
    const dejanje = b.dejanje;
    if (typeof dejanje === "string" && PREPOVEDANA.has(dejanje)) return napaka(res, 400, "action_not_allowed", "Cancelling or deleting events is not available in bulk (refunds are done one event at a time).");
    if (typeof dejanje !== "string" || !DEJANJA.has(dejanje)) return napaka(res, 400, "invalid_action", "dejanje must be pause, resume, draft or reschedule.");
    const surov = b.razlog !== undefined ? b.razlog : b.reason;
    const razlog = typeof surov === "string" ? surov.trim() : "";
    const dolzina = [...razlog].length;   // znaki Unicode (emoji = 1), kot char_length v bazi
    if (dolzina < RAZLOG_MIN || dolzina > RAZLOG_NAJVEC || NEVIDNI.test(typeof surov === "string" ? surov : "") || /[\u0000-\u001f\u007f-\u009f]/.test(typeof surov === "string" ? surov : "")) {
      return napaka(res, 400, "invalid_reason", `razlog is required: ${RAZLOG_MIN}-${RAZLOG_NAJVEC} characters, no control or invisible characters.`);
    }
    let zamik = null;
    if (dejanje === "reschedule") {
      zamik = b.zamik_min;
      if (!Number.isInteger(zamik) || zamik === 0 || Math.abs(zamik) > ZAMIK_NAJVEC_MIN) {
        return napaka(res, 400, "invalid_shift", `zamik_min must be a non-zero integer, at most ${ZAMIK_NAJVEC_MIN} minutes (30 days) either way.`);
      }
    } else if (b.zamik_min !== undefined && b.zamik_min !== null) return napaka(res, 400, "invalid_shift", "zamik_min is allowed only with reschedule.");

    const results = [], zacetek = Date.now();
    for (const id of ids) {   // zaporedno: en dogodek naenkrat (pool), vsak v svoji transakciji
      let izid;
      if (Date.now() - zacetek > PRORACUN_MS) { results.push({ id, ok: false, napaka: "not_processed", status: 503, message: "Not processed: the request ran out of time. Nothing was changed for this event; try again." }); continue; }
      try { izid = await eden(req, id, dejanje, razlog, zamik); }
      catch (e) { console.error(`[mnozicno] dogodek ${id}: ${e && e.message}`); izid = NAPAKA_STREZNIK; }
      results.push(izid.napaka ? { id, ok: false, ...izid } : { id, ok: true, ...izid });
    }
    console.log(`[mnozicno] admin ${req.user.userId}: ${dejanje}, dogodkov ${ids.length}, uspelo ${results.filter((r) => r.ok).length}`);
    return res.status(200).json({ dejanje, results });
  };
}

module.exports = { ustvari, IDOV_NAJVEC, ZAMIK_NAJVEC_MIN };
