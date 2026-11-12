"use strict";
// Izplacila klubom sele po dogodku (Issue #424 A; Martin 8. 11. 2026 12:50: »Outly nastavi izplacila klubom sele po dogodku«; 12. 11. 2026: zacni s sklopom; migracija 077, I72).
//
// Kaj: Connect racun kluba (Express, destination charge z on_behalf_of) dobi RECNA izplacila (settings.payouts.schedule.interval = manual). Kupnina ostane na Stripovem
// racunu kluba; ta delavec enkrat na uro izplaca na banko kluba SAMO tisto, kar ni zadrzano:
//   zadrzano = neto (total - refunded - provizija) vseh placanih narocil dogodkov, ki se niso »sprosceni«
//            + za odprte spore: pristojbine (IZPLACILA_SPOR_PRISTOJBINE_CENTS, privzeto 2 x 20 EUR) in, ce je dogodek ze sproscen, se znesek spora
//            + vracila za neaktivna narocila (inactive_order), ki se niso koncana (denar je na racunu kluba, transfer se bo obrnil).
//   izplacilo = na_voljo - max(0, zadrzano - v_cakanju)      (= min(na_voljo, vse - zadrzano); nikoli vec od na_voljo, nikoli zadrzanega denarja)
// Dogodek je sproscen: (a) admin je izplacilo odobril prej (izplacila_odobritve, POST /admin/api/events/:id/payout-early, sled v admin_dejanja), ali
// (b) ni odpovedan in danes (Europe/Ljubljana) je vsaj IZPLACILA_DNI_PO_DOGODKU (privzeto 2; Martin bo dokoncno odlocil) delovnih dni po dnevu konca (KONEC_DOGODKA:
// end_at, sicer start + 8 h). Delovni dan = pon-pet; prazniki NISO upostevani (predpostavka). Narocilo, placano pred vec kot IZPLACILA_NAJDLJE_DNI (85), se ne zadrzi vec:
// Stripe pri rocnih izplacilih dovoli drzati sredstva najvec 90 dni (docs.stripe.com/connect/manual-payouts, »All other countries: 90 days«).
//
// Zakaj je izracun iz STANJA na Stripu in ne iz vsote nasih narocil: vracila, povrnitve sporov in vracila provizije premikajo denar na racunu kluba; Stripovo stanje je resnica,
// mi dolocimo samo, koliko ga mora ostati. Ce je zadrzanega vec kot je na racunu, se ne izplaca nic (varna smer: zamuda, nikoli prevec).
// Dvojno izplacilo ni mogoce prevec: drugo izplacilo bi videlo ze zmanjsano stanje in izplacalo samo prost ostanek.
//
// Vklop: IZPLACILA_PO_DOGODKU=1 (Martin na Renderju; sprememba nastavitev Stripe racunov klubov je Martinova odlocitev). Izklopljeno: nic se ne spremeni (novi racuni kot doslej,
// noben klic Stripa), razen redkega POZOR, ce so racuni ze na rocnih izplacilih (denar bi obtical).
// Zanesljivost (I16): samo glavni pool, kratke poizvedbe, Stripovi klici zunaj transakcij in brez drzane povezave; najvec IZPLACILA_RACUNOV_NA_KROG racunov na krog.
// Vsak denarni klic ima idempotentni kljuc iz poslovne operacije (outly-izplacilo-<id>); vrstica `izplacila` v stanju v_teku (en na racun: delni UNIQUE indeks) je zahtevek.
const delavci = require("./delavci");

const LJ = "Europe/Ljubljana";
const KONEC = "COALESCE(e.end_at, e.start_at + INTERVAL '8 hours')";   // = KONEC_DOGODKA v index.js
const celo = (ime, privzeto, najmanj, najvec) => { const n = Number.parseInt(process.env[ime], 10); return Number.isInteger(n) && n >= najmanj && n <= najvec ? n : privzeto; };
const vklopljeno = () => process.env.IZPLACILA_PO_DOGODKU === "1";
const dniPoDogodku = () => celo("IZPLACILA_DNI_PO_DOGODKU", 2, 0, 10);
const najdljeDni = () => celo("IZPLACILA_NAJDLJE_DNI", 85, 1, 89);
const sporPristojbine = () => celo("IZPLACILA_SPOR_PRISTOJBINE_CENTS", 4000, 0, 100000);
const najmanjCents = () => celo("IZPLACILA_NAJMANJ_CENTS", 100, 1, 10000000);
// Nastavitev Connect racuna ob ustvarjanju (index.js stripeRacunKluba) in posodobitvi obstojecega.
const nastavitveRacuna = () => ({ payouts: { schedule: { interval: "manual" } } });
const jeRocen = (a) => !!(a && a.settings && a.settings.payouts && a.settings.payouts.schedule && a.settings.payouts.schedule.interval === "manual");

// Koledarski dan v Ljubljani (YYYY-MM-DD) in N delovnih dni (pon-pet) za njim.
const fmtDan = new Intl.DateTimeFormat("en-CA", { timeZone: LJ, year: "numeric", month: "2-digit", day: "2-digit" });
const danLJ = (d) => fmtDan.format(d instanceof Date ? d : new Date(d));
function plusDelovni(dan, n) {
  let t = Date.parse(dan + "T12:00:00Z"), k = 0;
  while (k < n) { t += 864e5; const wd = new Date(t).getUTCDay(); if (wd !== 0 && wd !== 6) k++; }
  return new Date(t).toISOString().slice(0, 10);
}
// Ali je dogodek sproscen za izplacilo ob casu `zdaj`.
function sproscen({ status, konec, prej }, zdaj = new Date(), n = dniPoDogodku()) {
  if (prej) return true;
  if (status === "cancelled" || !konec) return false;
  const k = konec instanceof Date ? konec : new Date(konec);
  if (zdaj < k) return false;
  return danLJ(zdaj) >= plusDelovni(danLJ(k), n);
}

function ustvari(dep) {
  const { pool, zapisiAdminDejanje, celoId4, odgovoriNaNapako } = dep;
  const stripe = dep.stripe;                 // () => Stripe odjemalec ali null (placila_stripe.stripe)
  const jeLive = dep.jeLive;
  const log = dep.log || console;
  const zdajFn = dep.zdaj || (() => new Date());   // samo za teste
  const RACUNOV_NA_KROG = celo("IZPLACILA_RACUNOV_NA_KROG", 50, 1, 1000);
  const ZASTARELO_MIN = 15;
  const kratko = (e) => `${e && e.type ? e.type : "Error"}${e && e.code ? " " + e.code : ""}: ${e && e.message ? e.message : String(e)}`.replace(/\s+/g, " ").slice(0, 300);
  const kljuc = (id) => `outly-izplacilo-${id}`;

  // --- urnik Connect racunov: interval = manual ---
  // Racuni klubov v TEKOCEM nacinu (I36), ki se nimajo potrjenega rocnega urnika. accounts.update je idempotenten (ista nastavitev), zato brez kljuca.
  async function urediUrnike(s) {
    const r = await pool.query(
      `SELECT c.id AS club_id, c.stripe_account_id
         FROM clubs c LEFT JOIN izplacila_racuni ir ON ir.stripe_account_id = c.stripe_account_id
        WHERE c.stripe_account_id IS NOT NULL AND c.stripe_account_id <> 'platform' AND COALESCE(c.stripe_account_livemode, FALSE) = $1
          AND (ir.stripe_account_id IS NULL OR (ir.rocno_at IS NULL AND ir.naslednji_at <= NOW()))
        ORDER BY c.id LIMIT $2`, [jeLive(), RACUNOV_NA_KROG]);
    let urejenih = 0;
    for (const x of r.rows) {
      try {
        const a = await s.accounts.update(x.stripe_account_id, { settings: nastavitveRacuna() });
        if (!jeRocen(a)) throw Object.assign(new Error("Stripe ni potrdil rocnega urnika izplacil"), { code: "urnik_ni_rocen" });
        await pool.query(
          `INSERT INTO izplacila_racuni (stripe_account_id, club_id, livemode, rocno_at) VALUES ($1, $2, $3, NOW())
           ON CONFLICT (stripe_account_id) DO UPDATE SET club_id = EXCLUDED.club_id, rocno_at = NOW(), napaka = NULL, poskusi = 0, posodobljen_at = NOW()`,
          [x.stripe_account_id, x.club_id, jeLive()]);
        urejenih++;
        log.log(`[izplacila] klub ${x.club_id}: Connect racun ima rocna izplacila`);
      } catch (e) {
        const opis = kratko(e);
        const v = await pool.query(
          `INSERT INTO izplacila_racuni (stripe_account_id, club_id, livemode, poskusi, naslednji_at, napaka) VALUES ($1, $2, $3, 1, NOW() + INTERVAL '30 minutes', $4)
           ON CONFLICT (stripe_account_id) DO UPDATE SET poskusi = izplacila_racuni.poskusi + 1, napaka = EXCLUDED.napaka, posodobljen_at = NOW(),
                  naslednji_at = NOW() + LEAST(INTERVAL '24 hours', (INTERVAL '30 minutes') * POWER(2, LEAST(izplacila_racuni.poskusi, 6)))
           RETURNING poskusi`, [x.stripe_account_id, x.club_id, jeLive(), opis]);
        log.error(`[izplacila] POZOR: klub ${x.club_id}: rocnega urnika izplacil ni bilo mogoce nastaviti (poskus ${v.rows[0].poskusi}): ${opis}. Do uspeha Stripe izplacuje klubu SAMODEJNO (tudi denar prihodnjih dogodkov).`);
      }
    }
    return urejenih;
  }

  // --- izracun zadrzanega zneska za klub/racun ---
  // Vrne { zadrzano, podrobnosti: [{ event_id, cents, vrsta }] }. Samo ID-ji in centi (brez osebnih podatkov).
  async function zadrzano(klubId, racun, zdaj = zdajFn()) {
    const n = dniPoDogodku(), najdlje = najdljeDni(), pristojbine = sporPristojbine();
    // Dogodki kluba z denarjem tega racuna, ki morda se niso sprosceni: konec v zadnjih 20 dneh ali v prihodnosti ali odpovedan (narocila mlajsa od `najdlje` dni).
    const ev = await pool.query(
      `SELECT e.id AS event_id, e.status, ${KONEC} AS konec, (od.event_id IS NOT NULL) AS prej,
              COALESCE(SUM(GREATEST(0, o.total_cents - COALESCE(o.refunded_cents, 0) - COALESCE(o.application_fee_cents, 0)))
                FILTER (WHERE o.paid_at > $4::timestamptz - ($3::int * INTERVAL '1 day')), 0)::bigint AS neto,
              COALESCE(SUM(GREATEST(0, o.total_cents - COALESCE(o.refunded_cents, 0) - COALESCE(o.application_fee_cents, 0)))
                FILTER (WHERE o.paid_at <= $4::timestamptz - ($3::int * INTERVAL '1 day')), 0)::bigint AS neto_star
         FROM events e JOIN orders o ON o.event_id = e.id
         LEFT JOIN izplacila_odobritve od ON od.event_id = e.id
        WHERE e.club_id = $1 AND (e.status = 'cancelled' OR ${KONEC} > $4::timestamptz - INTERVAL '20 days')
          AND o.stripe_account_id = $2 AND o.status IN ('paid', 'partially_refunded') AND o.total_cents > 0 AND o.guest_list_id IS NULL
          AND COALESCE(o.stripe_payment_intent_id, '') NOT LIKE 'test\\_%' AND o.paid_at > $4::timestamptz - INTERVAL '120 days'
        GROUP BY e.id, e.status, e.end_at, e.start_at, od.event_id`, [klubId, racun, najdlje, zdaj]);
    const nesproscen = new Set();
    const podrobnosti = [], rokHrambe = [];
    let vsota = 0;
    for (const x of ev.rows) {
      if (sproscen({ status: x.status, konec: x.konec, prej: x.prej }, zdaj, n)) continue;
      nesproscen.add(Number(x.event_id));
      const c = Number(x.neto) || 0;
      if (c > 0) { vsota += c; podrobnosti.push({ event_id: Number(x.event_id), cents: c, vrsta: "dogodek" }); }
      // Pogodba 7. clen (»Ce Stripe sredstev ne dovoli zadrzati do konca dogodka, jih izplaca prej«): denar nesproscenega dogodka, star vec kot `najdlje` dni,
      // se NE zadrzi (gre ven s tem izplacilom); zapis v podrobnosti (vrsta rok_hrambe, ne steje v zadrzano) in POZOR v izplacajRacun.
      const star = Number(x.neto_star) || 0;
      if (star > 0) { podrobnosti.push({ event_id: Number(x.event_id), cents: star, vrsta: "rok_hrambe" }); rokHrambe.push({ event_id: Number(x.event_id), cents: star }); }
    }
    // Odprti spori (tudi poizvedbe: lahko preidejo v spor) in izgubljeni s se neopravljeno povrnitvijo od kluba.
    const sp = await pool.query(
      `SELECT o.event_id, sp.znesek_cents FROM spori sp JOIN orders o ON o.id = sp.order_id
        WHERE o.stripe_account_id = $1 AND o.club_id = $2
          AND (sp.zaprt_at IS NULL OR (sp.stanje = 'lost' AND sp.povrnitev_stanje IN ('caka', 'v_teku', 'ni_uspelo')))
          AND sp.stanje NOT IN ('won', 'warning_closed', 'prevented')`, [racun, klubId]);
    for (const x of sp.rows) {
      const c = pristojbine + (nesproscen.has(Number(x.event_id)) ? 0 : (Number(x.znesek_cents) || 0));   // nesproscen dogodek: neto narocila je ze zadrzan
      if (c > 0) { vsota += c; podrobnosti.push({ event_id: Number(x.event_id), cents: c, vrsta: "spor" }); }
    }
    // Vracila neaktivnih narocil (denar je na racunu kluba, reverse_transfer ga bo vzel), se ne koncana.
    const vr = await pool.query(
      `SELECT v.event_id, COALESCE(v.znesek_cents, o.total_cents) AS cents FROM vracila v JOIN orders o ON o.id = v.order_id
        WHERE o.stripe_account_id = $1 AND o.club_id = $2 AND v.razlog = 'inactive_order' AND v.stanje IN ('caka', 'v_teku', 'potrditev', 'ni_uspelo')`, [racun, klubId]);
    for (const x of vr.rows) {
      const c = Number(x.cents) || 0;
      if (c > 0) { vsota += c; podrobnosti.push({ event_id: Number(x.event_id), cents: c, vrsta: "vracilo" }); }
    }
    return { zadrzano: vsota, podrobnosti, rokHrambe };
  }

  const eur = (seznam) => (Array.isArray(seznam) ? seznam : []).filter((x) => String(x.currency || "").toLowerCase() === "eur").reduce((a, x) => a + (Number(x.amount) || 0), 0);

  // Najde Stripovo izplacilo te vrstice (crash po klicu, napaka omrezja po tem, ko je Stripe izplacilo ustvaril): po metadata.izplacilo_id.
  async function najdiIzplacilo(s, racun, id) {
    const sez = await s.payouts.list({ limit: 100 }, { stripeAccount: racun });
    return (sez.data || []).find((p) => p.metadata && p.metadata.izplacilo_id === String(id)) || null;
  }

  // Eno izplacilo za racun. Vrne { stanje, znesek? } (za teste in dnevnik).
  async function izplacajRacun(s, klubId, racun) {
    // Po zavrnjenem izplacilu (napacen IBAN ipd.) 24 h ne poskusamo znova (alarm je ze sel; admin uredi v Stripu).
    const padlo = await pool.query(`SELECT 1 FROM izplacila WHERE stripe_account_id = $1 AND stanje = 'ni_uspelo' AND posodobljeno_at > NOW() - INTERVAL '24 hours' LIMIT 1`, [racun]);
    if (padlo.rowCount) return { stanje: "odlozeno" };
    const z = await pool.query(
      `INSERT INTO izplacila (club_id, stripe_account_id, livemode) VALUES ($1, $2, $3) ON CONFLICT (stripe_account_id) WHERE stanje = 'v_teku' DO NOTHING RETURNING id`,
      [klubId, racun, jeLive()]);
    if (!z.rowCount) return { stanje: "v_teku" };   // drug proces ali obvisela vrstica (pospravi())
    const id = z.rows[0].id;
    let znesek = null;
    try {
      const zad = await zadrzano(klubId, racun);
      const b = await s.balance.retrieve({}, { stripeAccount: racun });
      const naVoljo = eur(b.available), vCakanju = eur(b.pending);
      znesek = naVoljo - Math.max(0, zad.zadrzano - vCakanju);
      if (znesek < najmanjCents()) {
        await pool.query("DELETE FROM izplacila WHERE id = $1 AND stanje = 'v_teku'", [id]);
        return { stanje: "nic", na_voljo: naVoljo, zadrzano: zad.zadrzano };
      }
      await pool.query(
        `UPDATE izplacila SET znesek_cents = $2, zadrzano_cents = $3, na_voljo_cents = $4, v_cakanju_cents = $5, podrobnosti = $6::jsonb, posodobljeno_at = NOW() WHERE id = $1`,
        [id, znesek, zad.zadrzano, naVoljo, vCakanju, JSON.stringify(zad.podrobnosti.slice(0, 200))]);
      const p = await s.payouts.create({ amount: znesek, currency: "eur", metadata: { izplacilo_id: String(id), club_id: String(klubId) } },
        { stripeAccount: racun, idempotencyKey: kljuc(id) });
      await pool.query("UPDATE izplacila SET stanje = 'poslano', payout_id = $2, stripe_stanje = $3, posodobljeno_at = NOW() WHERE id = $1", [id, p.id, String(p.status || "").slice(0, 30) || null]);
      log.log(`[izplacila] klub ${klubId}: izplacilo ${id} ${znesek} c (na voljo ${naVoljo}, zadrzano ${zad.zadrzano}, v cakanju ${vCakanju})`);
      // Pogodba 7. clen: denar prihodnjega dogodka, ki ga Stripe ne dovoli drzati dlje (> IZPLACILA_NAJDLJE_DNI po placilu), je sel ven s tem izplacilom.
      // Zapis je v podrobnosti (vrsta rok_hrambe); POZOR (Sentry) samo prvic za dogodek (prejsnja poslana/placana izplacila ga ze nosijo -> brez ponavljanja vsako uro).
      if (zad.rokHrambe.length) {
        const prej = new Set((await pool.query(
          `SELECT DISTINCT (x->>'event_id')::int AS e FROM izplacila i, jsonb_array_elements(i.podrobnosti) x
            WHERE i.stripe_account_id = $1 AND i.id <> $2 AND i.stanje IN ('poslano', 'placano') AND x->>'vrsta' = 'rok_hrambe'`, [racun, id])).rows.map((x) => x.e));
        const novi = zad.rokHrambe.filter((x) => !prej.has(x.event_id));
        if (novi.length) log.error(`[izplacila] POZOR: klub ${klubId}: denar prihodnjih dogodkov je bil na racunu kluba vec kot ${najdljeDni()} dni (Stripe dovoli najvec 90), zato je izplacan PRED dogodkom z izplacilom ${id} (pogodba 7. clen): ${novi.map((x) => `dogodek ${x.event_id}: ${x.cents} c`).join(", ")}. Ob odpovedi ali sporu vracilo pokrije klub iz drugega denarja.`);
      }
      return { stanje: "poslano", znesek, zadrzano: zad.zadrzano };
    } catch (e) {
      // Je Stripe izplacilo morda vseeno ustvaril (rok omrezja)? Poisci po metadata; sicer vrstica ni_uspelo (naslednji krog naredi novo z novim stanjem).
      let p = null;
      if (znesek !== null && znesek >= najmanjCents()) { try { p = await najdiIzplacilo(s, racun, id); } catch (_) { p = null; } }
      if (p) {
        await pool.query("UPDATE izplacila SET stanje = 'poslano', payout_id = $2, stripe_stanje = $3, znesek_cents = $4, posodobljeno_at = NOW() WHERE id = $1", [id, p.id, String(p.status || "").slice(0, 30) || null, p.amount]);
        return { stanje: "poslano", znesek: p.amount };
      }
      if (znesek === null || znesek < najmanjCents()) await pool.query("DELETE FROM izplacila WHERE id = $1 AND stanje = 'v_teku'", [id]);
      else await pool.query("UPDATE izplacila SET stanje = 'ni_uspelo', napaka = $2, posodobljeno_at = NOW() WHERE id = $1 AND stanje = 'v_teku'", [id, kratko(e)]);
      log.error(`[izplacila] POZOR: klub ${klubId}: izplacilo ${id}${znesek ? " " + znesek + " c" : ""} ni uspelo: ${kratko(e)}. Denar ostane na Stripovem racunu kluba; naslednji poskus cez 24 h ali po pregledu v Stripu.`);
      return { stanje: "ni_uspelo" };
    }
  }

  // Obvisele v_teku (proces ugasnjen med klicem): posvoji Stripovo izplacilo po metadata ali zapri kot ni_uspelo (brez denarja na poti).
  async function pospravi(s) {
    const r = await pool.query(`SELECT id, club_id, stripe_account_id, znesek_cents FROM izplacila WHERE stanje = 'v_teku' AND prevzeto_at < NOW() - ($1::int * INTERVAL '1 minute') LIMIT 20`, [ZASTARELO_MIN]);
    for (const x of r.rows) {
      let p = null;
      try { p = x.znesek_cents ? await najdiIzplacilo(s, x.stripe_account_id, x.id) : null; } catch (e) { log.error(`[izplacila] pospravljanje ${x.id}: ${kratko(e)}`); continue; }
      if (p) await pool.query("UPDATE izplacila SET stanje = 'poslano', payout_id = $2, stripe_stanje = $3, znesek_cents = $4, posodobljeno_at = NOW() WHERE id = $1 AND stanje = 'v_teku'", [x.id, p.id, String(p.status || "").slice(0, 30) || null, p.amount]);
      else await pool.query("UPDATE izplacila SET stanje = 'ni_uspelo', napaka = 'obviselo v_teku, izplacila v Stripu ni', posodobljeno_at = NOW() - INTERVAL '24 hours' WHERE id = $1 AND stanje = 'v_teku'", [x.id]);
    }
  }

  // Izid poslanih izplacil (paid | failed | canceled); pending/in_transit ostanejo poslano.
  async function preveriPoslana(s) {
    const r = await pool.query(
      `SELECT id, club_id, stripe_account_id, payout_id, znesek_cents FROM izplacila WHERE stanje = 'poslano' AND payout_id IS NOT NULL AND posodobljeno_at < NOW() - INTERVAL '30 minutes'
        ORDER BY posodobljeno_at LIMIT 20`);
    for (const x of r.rows) {
      try {
        const p = await s.payouts.retrieve(x.payout_id, {}, { stripeAccount: x.stripe_account_id });
        const st = String(p.status || "").slice(0, 30);
        if (st === "paid") await pool.query("UPDATE izplacila SET stanje = 'placano', stripe_stanje = $2, posodobljeno_at = NOW() WHERE id = $1 AND stanje = 'poslano'", [x.id, st]);
        else if (st === "failed" || st === "canceled") {
          await pool.query("UPDATE izplacila SET stanje = 'ni_uspelo', stripe_stanje = $2, napaka = $3, posodobljeno_at = NOW() WHERE id = $1 AND stanje = 'poslano'", [x.id, st, String(p.failure_code || st).slice(0, 100)]);
          log.error(`[izplacila] POZOR: klub ${x.club_id}: izplacilo ${x.id} (${x.znesek_cents} c) je Stripe zavrnil (${p.failure_code || st}); denar je spet na racunu kluba. Preveri bancni racun kluba v Stripu.`);
        } else await pool.query("UPDATE izplacila SET stripe_stanje = $2, posodobljeno_at = NOW() WHERE id = $1", [x.id, st]);
      } catch (e) { log.error(`[izplacila] preverba izplacila ${x.id}: ${kratko(e)}`); }
    }
  }

  let tece = false;
  let utrip = delavci.BREZ;
  // En krog. Nikoli ne vrze. Vrne povzetek (za teste).
  async function krog() {
    if (tece) return { preskoceno: "tece" };
    tece = true;
    const k = utrip.zacetek();
    const izid = { urnikov: 0, racuni: [] };
    try {
      const s = stripe && stripe();
      if (!s) return { preskoceno: "brez_kljuca" };
      if (!vklopljeno()) {
        const r = await pool.query("SELECT COUNT(*)::int AS n FROM izplacila_racuni WHERE rocno_at IS NOT NULL AND livemode = $1", [jeLive()]);
        if (r.rows[0].n > 0) delavci.pozorRedko("izplacila:izklopljeno", `Izplacila: ${r.rows[0].n} Connect racunov klubov je na ROCNIH izplacilih, IZPLACILA_PO_DOGODKU pa ni 1: klubom se nic ne izplacuje (Stripe dovoli drzati najvec 90 dni). Vklopi IZPLACILA_PO_DOGODKU=1 ali urnik vrni v Stripu.`);
        return { preskoceno: "izklopljeno" };
      }
      izid.urnikov = await urediUrnike(s);
      await pospravi(s);
      const r = await pool.query(
        `SELECT c.id AS club_id, c.stripe_account_id FROM clubs c JOIN izplacila_racuni ir ON ir.stripe_account_id = c.stripe_account_id
          WHERE ir.rocno_at IS NOT NULL AND ir.livemode = $1 AND COALESCE(c.stripe_account_livemode, FALSE) = $1 AND c.stripe_payouts_enabled
          ORDER BY c.id LIMIT $2`, [jeLive(), RACUNOV_NA_KROG]);
      for (const x of r.rows) {
        try { izid.racuni.push({ club_id: x.club_id, ...(await izplacajRacun(s, x.club_id, x.stripe_account_id)) }); }
        catch (e) { log.error(`[izplacila] klub ${x.club_id}: ${kratko(e)}`); }
      }
      await preveriPoslana(s);
      return izid;
    } catch (e) {
      log.error(`[izplacila] krog: ${kratko(e)}`);
      return { ...izid, napaka: kratko(e) };
    } finally { k.konec(); tece = false; }
  }

  let casovnik = null;
  function zazeni() {
    const tik = celo("IZPLACILA_TIK_MS", 60 * 60 * 1000, 100, 24 * 3600 * 1000);
    const zagon = process.env.IZPLACILA_ZAGON_MS !== undefined ? celo("IZPLACILA_ZAGON_MS", 0, 0, 3600000) : 120000 + Math.round(Math.random() * 480000);
    utrip = delavci.registriraj("izplacila", { periodaMs: tik, zamikMs: zagon });
    const prvi = setTimeout(() => { void krog(); casovnik = setInterval(() => { void krog(); }, tik); casovnik.unref(); }, zagon);
    prvi.unref();
    return { ustavi: () => { clearTimeout(prvi); if (casovnik) clearInterval(casovnik); } };
  }
  const zbudi = () => { setTimeout(() => { void krog(); }, 50).unref(); };

  // --- admin ---
  function registriraj(router) {
    // GET /admin/api/payouts?club_id=&limit= — zadnja izplacila (brez osebnih podatkov) in nastavitve.
    router.get("/payouts", async (req, res) => {
      try {
        res.set("Cache-Control", "no-store");
        const klub = req.query.club_id === undefined ? null : celoId4(req.query.club_id);
        if (req.query.club_id !== undefined && !klub) return res.status(400).json({ error: "invalid_club", message: "club_id must be a club id." });
        const lim = Math.min(200, Math.max(1, celoId4(req.query.limit) || 50));
        const r = await pool.query(
          `SELECT i.id, i.club_id, c.name AS club_name, i.stanje AS state, i.znesek_cents AS amount_cents, i.valuta AS currency, i.zadrzano_cents AS held_cents,
                  i.na_voljo_cents AS available_cents, i.v_cakanju_cents AS pending_cents, i.payout_id, i.stripe_stanje AS stripe_state, i.napaka AS error,
                  i.ustvarjeno_at AS created_at, i.posodobljeno_at AS updated_at, i.podrobnosti AS held
             FROM izplacila i LEFT JOIN clubs c ON c.id = i.club_id
            WHERE ($1::int IS NULL OR i.club_id = $1) ORDER BY i.ustvarjeno_at DESC, i.id DESC LIMIT $2`, [klub, lim]);
        const racuni = await pool.query(
          `SELECT ir.club_id, ir.rocno_at AS manual_since, ir.napaka AS error, ir.poskusi AS attempts FROM izplacila_racuni ir WHERE ($1::int IS NULL OR ir.club_id = $1) ORDER BY ir.club_id LIMIT 500`, [klub]);
        return res.json({ enabled: vklopljeno(), days_after_event: dniPoDogodku(), max_hold_days: najdljeDni(), items: r.rows, accounts: racuni.rows });
      } catch (e) {
        if (odgovoriNaNapako) return odgovoriNaNapako(res, e, "GET /admin/api/payouts");
        return res.status(500).json({ error: "internal_error", message: "Internal error." });
      }
    });

    // POST /admin/api/events/:id/payout-early { reason } — admin odobri izplacilo denarja dogodka pred rokom (sled v admin_dejanja v isti transakciji).
    router.post("/events/:id/payout-early", async (req, res) => {
      const id = celoId4(req.params.id);
      if (!id) return res.status(400).json({ error: "invalid_event", message: "Invalid event id." });
      const razlog = typeof (req.body && req.body.reason) === "string" ? req.body.reason.trim() : "";
      if (razlog.length < 3 || razlog.length > 500) return res.status(400).json({ error: "invalid_reason", message: "reason must be 3 to 500 characters." });
      const c = await pool.connect();
      try {
        await c.query("BEGIN");
        await c.query("SET LOCAL lock_timeout = '3s'");
        const e = await c.query("SELECT e.id, cl.is_official FROM events e JOIN clubs cl ON cl.id = e.club_id WHERE e.id = $1", [id]);
        if (!e.rows.length) { await c.query("ROLLBACK"); return res.status(404).json({ error: "not_found", message: "Event not found." }); }
        if (e.rows[0].is_official === true) { await c.query("ROLLBACK"); return res.status(409).json({ error: "platform_event", message: "Outly's own events are paid directly to Outly; there is no club payout." }); }
        const v = await c.query(
          "INSERT INTO izplacila_odobritve (event_id, admin_user_id, razlog) VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING RETURNING odobreno_at",
          [id, req.user && Number.isInteger(req.user.userId) ? req.user.userId : null, razlog]);
        if (v.rowCount) await zapisiAdminDejanje(c, req, "event.payout_early", "event", id, { payout_early: false }, { payout_early: true }, razlog);
        await c.query("COMMIT");
        if (v.rowCount && vklopljeno()) zbudi();
        return res.json({ ok: true, already: !v.rowCount, enabled: vklopljeno() });
      } catch (err) {
        await c.query("ROLLBACK").catch(() => {});
        if (odgovoriNaNapako) return odgovoriNaNapako(res, err, "POST /admin/api/events/:id/payout-early");
        return res.status(500).json({ error: "internal_error", message: "Internal error." });
      } finally { c.release(); }
    });
  }

  return { krog, zazeni, zbudi, registriraj, zadrzano, izplacajRacun, urediUrnike };
}

module.exports = { ustvari, vklopljeno, nastavitveRacuna, jeRocen, sproscen, plusDelovni, danLJ, dniPoDogodku };
