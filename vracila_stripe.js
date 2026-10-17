// Vracila (issue #190, prva faza): odpoved dogodka -> vracilo VSEM placanim narocilom; placilo za neaktivno narocilo -> samodejno vracilo.
//
// Odlocitev Martina (12. 10. 2026, DECISIONS): kupec ob odpovedi dogodka dobi CELOTEN znesek. Glavnico vrne klub (reverse_transfer), Outly vrne svojo
// provizijo, Stripovo pristojbino za prvotno placilo (Stripe je ob vracilu ne vrne, placala jo je platforma) nosi klub.
//
// Kako to izvede Stripe (destination charge z application_fee_amount; docs.stripe.com/connect/destination-charges, razdelek »Issue refunds«):
//   - Na Connect racun kluba gre ob placilu CEL znesek, provizija se prenese platformi.
//   - refunds.create z `reverse_transfer: true` obrne CEL transfer (ob polnem vracilu), vendar provizija ostane pri platformi: klub bi nosil znesek + provizijo.
//   - `refund_application_fee: true` bi platformi vzel celo provizijo (klub bi bil na nic), a Stripova pristojbina (platforma jo je placala) bi ostala pri platformi.
//   - Ker mora pristojbino nositi klub, ODPOVED DOGODKA uporabi `refund_application_fee: false` in nato SAMOSTOJNO vracilo provizije
//     (applicationFees.createRefund) v znesku provizija - Stripova pristojbina (kar je ze vrnjeno iz provizije, se odsteje). Klub tako nosi pristojbino, platforma nic.
//     Ce je pristojbina vecja od provizije (poceni vstopnice), je vracilo provizije 0 in razliko nosi Outly.
//   - PLACILO ZA NEAKTIVNO NAROCILO (`inactive_order`) je nasa napaka: `reverse_transfer: true` + `refund_application_fee: true` v enem klicu, Stripovo pristojbino nosi Outly.
//
// Zanesljivost (Martinova zahteva: 1000+ hkratnih uporabnikov, sken vstopnic ne sme pasti): masovno vracilo NE tece v zahtevku. Odpoved dogodka samo VSTAVI vrstice v
// `vracila` (en INSERT ... SELECT, brez Stripa); ta obdelovalec jih po eno prevzema (FOR UPDATE SKIP LOCKED), z razmikom med klici (VRACILA_RAZMAK_MS), najvec eno
// naroceno naenkrat (ena povezava iz pool-a v kratkih poizvedbah, nikoli drzana med klicem Stripa) in ponovitvami z narascajocim premorom. Vsak Stripov klic ima idempotentni
// kljuc (`outly-vracilo-<id>`, `outly-vracilo-<id>-provizija`), korake pa nosi vrstica (stripe_vracilo_id, provizija_vracilo_id): ponovni zagon ne vrne dvakrat.
//
// Stanja: caka -> v_teku -> opravljeno | potrditev (Stripe je vracilo sprejel kot `pending` ali `requires_action` (kupec dobi navodila, vracilo se nadaljuje); izid pride z webhookom refund.* / charge.refund.updated ali ga prebere tek) |
// ni_uspelo (alarm, admin ponovi) | rocno (alarm; drug nacin Stripa, brez kljuca, nepricakovano stanje) | preklicano (dogodek obnovljen; ponovna odpoved ga vrne v `caka`).
// Vsak prehod v ni_uspelo/rocno (in Stripova zavrnitev vrstice, ki je ze v enem od njiju) nastavi `ni_izvedeno_od_at = NOW()` (051, #251), admin retry ga
// pocisti: iz njega index.js steje rok za mail kupcu `ni_izvedeno` (VRACILA_NI_IZVEDENO_PO_MS).
//
// Vrstni red v izvedi(): A) vracilo kupcu (idempotentni kljuc) -> lokalno stanje narocila -> B) vracilo provizije (po A, da kupec ne caka na racunovodske podatke) -> zakljucek.
// Ko je `stripe_vracilo_id` zapisan, se korak A in njegove preverbe NIKOLI ne ponovijo (webhook je naroceno medtem lahko ze oznacil `refunded`): nadaljuje se s korakom B.
"use strict";
const placila = require("./placila_stripe");

const celo = (ime, privzeto, najmanj, najvec) => { const n = Number.parseInt(process.env[ime], 10); return Number.isInteger(n) && n >= najmanj && n <= najvec ? n : privzeto; };
const spi = (ms) => new Promise((r) => setTimeout(r, ms));
// Premor pred naslednjim poskusom (po stevilu opravljenih poskusov): 30 s, 2 min, 10 min, 30 min, 2 h, 6 h, 12 h. VRACILA_PREMOR_MS ga za teste nadomesti s stalno vrednostjo.
const PREMORI_MS = [30e3, 120e3, 600e3, 1800e3, 7200e3, 21600e3, 43200e3];

// Napaka, ki zahteva cloveka (ne ponavljamo): drug nacin Stripa, brez kljuca, nepricakovano stanje.
class Rocno extends Error {}

function ustvari({ pool, naKoncano, posljiNeposlane }) {
  const TICK_MS = celo("VRACILA_TICK_MS", 10000, 0, 3600000);          // 0 = obdelovalec izklopljen (testi)
  const RAZMAK_MS = celo("VRACILA_RAZMAK_MS", 250, 0, 60000);          // premor med naroceni (omejitev hitrosti: ~4 vracila/s)
  const PAKET = celo("VRACILA_PAKET", 20, 1, 200);
  const NAJVEC_POSKUSOV = celo("VRACILA_POSKUSOV", 8, 1, 50);
  const PREMOR_MS = celo("VRACILA_PREMOR_MS", 0, 0, 86400000);
  const ZAMIK_S = celo("VRACILA_ZAMIK_S", 60, 0, 86400);              // odlog zacetka vracil po odpovedi (zmota lastnika: dogodek se obnovi, preden steče denar)
  const SWEEP_MS = celo("VRACILA_SWEEP_MS", 60000, 0, 3600000);
  const POTRDITEV_MS = celo("VRACILA_POTRDITEV_MS", 3600000, 100, 86400000);   // kako pogosto tek sprasuje Stripe po vracilih v stanju `potrditev`
  const PRORACUN_MS = 45000;                                           // najdlje en tek (potem mail in nov tek)
  const ZASTARELO_MIN = 10;                                            // prevzeto vracilo brez zakljucka (proces ugasnjen) se vrne v vrsto

  const premorPoPoskusu = (poskusi) => (PREMOR_MS > 0 ? PREMOR_MS : PREMORI_MS[Math.min(Math.max(poskusi, 1), PREMORI_MS.length) - 1]);
  const kljucA = (v) => `outly-vracilo-${v.id}${v.kljuc_gen ? "-g" + v.kljuc_gen : ""}`;
  const kljucB = (v) => `outly-vracilo-${v.id}-provizija${v.kljuc_gen ? "-g" + v.kljuc_gen : ""}`;

  // Odpoved dogodka: vstavi vrstice za VSA placana narocila dogodka (en stavek, brez Stripa; guest lista ni prodaja). c = povezava klicatelja (transakcija odpovedi) ali pool.
  // Ponovna odpoved (odpoved -> obnova v zamiku -> `preklicano` -> nova odpoved): vrstica `preklicano` se vrne v `caka`; druga stanja se ne dotaknejo (UNIQUE order_id, razlog).
  const VSTAVI_VRACILA = `INSERT INTO vracila (order_id, event_id, razlog, naslednji_poskus_at, mail_odpoved_po_at)
       SELECT o.id, o.event_id, 'event_cancelled', t.cas, t.cas FROM (SELECT NOW() + ($2::int * INTERVAL '1 second') AS cas) t, orders o
        WHERE o.event_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL
       ON CONFLICT (order_id, razlog) DO UPDATE SET stanje = 'caka', poskusi = 0, napaka = NULL, naslednji_poskus_at = EXCLUDED.naslednji_poskus_at,
              mail_odpoved_po_at = EXCLUDED.mail_odpoved_po_at WHERE vracila.stanje = 'preklicano'`;
  async function vrstiZaDogodek(c, eventId, zamikS = ZAMIK_S) {
    // Izrecna odpoved (tudi ze odpovedanega dogodka, ki ga sprozilec ni zabelezil): dogodek odslej spremlja sweep (placilo, ki prispe po odpovedi).
    await c.query("INSERT INTO odpovedi_dogodkov (event_id) VALUES ($1) ON CONFLICT (event_id) DO UPDATE SET odpovedan_at = NOW()", [eventId]);
    const r = await c.query(VSTAVI_VRACILA, [eventId, zamikS]);
    return r.rowCount;
  }

  // Varovalka: dogodek odpovedan po drugi poti (PATCH /events/:id, admin, SQL) ali placilo, ki je prispelo po odpovedi, nista ostala brez vracila.
  // SAMO dogodki iz `odpovedi_dogodkov`, odpovedani v zadnjih 30 dneh (starejsih odpovedanih dogodkov sweep ne dotakne; izrecen DELETE jih osvezi).
  let zadnjiSweep = 0;
  async function pomeni() {
    if (SWEEP_MS <= 0 || Date.now() - zadnjiSweep < SWEEP_MS) return 0;
    zadnjiSweep = Date.now();
    const r = await pool.query(
      `INSERT INTO vracila (order_id, event_id, razlog, naslednji_poskus_at, mail_odpoved_po_at)
       SELECT o.id, o.event_id, 'event_cancelled', t.cas, t.cas
         FROM (SELECT NOW() + ($1::int * INTERVAL '1 second') AS cas) t, odpovedi_dogodkov od JOIN events e ON e.id = od.event_id AND e.status = 'cancelled'
         JOIN orders o ON o.event_id = e.id AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL
        WHERE od.odpovedan_at > NOW() - INTERVAL '30 days'
          AND NOT EXISTS (SELECT 1 FROM vracila v WHERE v.order_id = o.id AND v.razlog = 'event_cancelled' AND v.stanje <> 'preklicano')
        LIMIT 2000
       ON CONFLICT (order_id, razlog) DO UPDATE SET stanje = 'caka', poskusi = 0, napaka = NULL, naslednji_poskus_at = EXCLUDED.naslednji_poskus_at,
              mail_odpoved_po_at = EXCLUDED.mail_odpoved_po_at WHERE vracila.stanje = 'preklicano'`, [ZAMIK_S]);
    if (r.rowCount) console.log(`[vracila] sweep: ${r.rowCount} narocil odpovedanih dogodkov dodanih v vrsto`);
    return r.rowCount;
  }

  async function sprostiZastarele() {
    const r = await pool.query(
      `UPDATE vracila SET stanje = 'caka', naslednji_poskus_at = NOW() WHERE stanje = 'v_teku' AND prevzeto_at < NOW() - ($1::int * INTERVAL '1 minute') RETURNING id`, [ZASTARELO_MIN]);
    if (r.rowCount) console.error(`[vracila] POZOR: ${r.rowCount} vracil je viselo v stanju v_teku vec kot ${ZASTARELO_MIN} min (proces ugasnjen med vracilom?); vrnjena v vrsto, idempotentni kljuc prepreci dvojno vracilo.`);
  }

  async function prevzemi(n) {
    const r = await pool.query(
      `UPDATE vracila SET stanje = 'v_teku', prevzeto_at = NOW(), poskusi = poskusi + 1
        WHERE id IN (SELECT id FROM vracila WHERE stanje = 'caka' AND naslednji_poskus_at <= NOW() ORDER BY naslednji_poskus_at, id LIMIT $1 FOR UPDATE SKIP LOCKED)
        RETURNING id`, [n]);
    return r.rows.map((x) => x.id).sort((a, b) => Number(a) - Number(b));
  }

  async function vTransakciji(fn) {
    const c = await pool.connect();
    try { await c.query("BEGIN"); const rez = await fn(c); await c.query("COMMIT"); return rez; }
    catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
    finally { c.release(); }
  }

  const kratko = (e) => `${e && e.type ? e.type : "Error"}${e && e.code ? " " + e.code : ""}: ${e && e.message ? e.message : String(e)}`.replace(/\s+/g, " ").slice(0, 300);
  const zapri = (id, stanje, napaka) => pool.query(
    `UPDATE vracila SET stanje = $2, napaka = $3, opravljeno_at = CASE WHEN $2 = 'opravljeno' THEN NOW() ELSE opravljeno_at END,
            ni_izvedeno_od_at = CASE WHEN $2 IN ('ni_uspelo', 'rocno') THEN NOW() ELSE ni_izvedeno_od_at END WHERE id = $1 AND stanje = 'v_teku'`, [id, stanje, napaka || null]);

  // Lokalno stanje narocila po vracilu (isto kot webhook charge.refunded: placila.uveljaviVracilo), idempotentno. Odpoved dogodka vrne VSE (kupec dobi celoten znesek).
  // Za inactive_order narocila ne spreminjamo (ostane cancelled/failed, vstopnic ni).
  async function uveljaviLokalno(v) {
    if (v.razlog !== "event_cancelled") return;
    await vTransakciji(async (c) => {
      const o = (await c.query("SELECT id, public_ref, total_cents, refunded_cents, status FROM orders WHERE id = $1 FOR UPDATE", [v.order_id])).rows[0];
      if (o && ["paid", "partially_refunded", "refunded"].includes(o.status)) await placila.uveljaviVracilo(c, o, o.total_cents, null);
    });
  }

  // Zakljucek vrstice (stanje `opravljeno`) + lokalno stanje v ENI transakciji.
  async function opravi(v, znesek, opomba, brezStripa) {   // brezStripa: samo stanje (0 EUR, testni nacin)
    await vTransakciji(async (c) => {
      const o = (await c.query("SELECT id, public_ref, total_cents, refunded_cents, status FROM orders WHERE id = $1 FOR UPDATE", [v.order_id])).rows[0];
      if (v.razlog === "event_cancelled" && o && ["paid", "partially_refunded", "refunded"].includes(o.status)) await placila.uveljaviVracilo(c, o, o.total_cents, null);
      await c.query(
        `UPDATE vracila SET stanje = 'opravljeno', opravljeno_at = NOW(), napaka = $2, znesek_cents = $3, brez_stripa = $4 WHERE id = $1`,
        [v.id, opomba || null, znesek, !!brezStripa]);
    });
    console.log(`[vracila] opravljeno: narocilo ${v.public_ref} (${v.razlog}), ${znesek} c${brezStripa ? ", brez Stripa" : ""}${opomba ? " [" + opomba + "]" : ""}`);
    if (naKoncano) { try { Promise.resolve(naKoncano(v.id)).catch((e) => console.error("[vracila] obvestilo:", e && e.message)); } catch (e) { console.error("[vracila] obvestilo:", e && e.message); } }
  }

  // Stripov napaka: trajna (ponovitev ne pomaga) ali prehodna (omrezje, 5xx, omejitev hitrosti).
  const STRIPE_NEDOKONCNO = ["failed", "canceled"];   // Stripovo vracilo zavrnjeno: admin retry ni dovoljen (409), glej ponovi(). `requires_action` NI zavrnitev (kupec dobi navodila, vracilo se nadaljuje): obravnava kot `pending`
  // Kupec je vrnjen (ali je vracilo na poti), ce Stripe vracilo obstaja in ni zavrnjeno; zavrnjeno vracilo je v vrstici zapisano (stripe_vracilo_id), a denarja ni.
  const stripeZavrnil = (v) => !!v.stripe_vracilo_id && STRIPE_NEDOKONCNO.includes(v.stripe_stanje);
  const kupecVrnjen = (v) => !!v.stripe_vracilo_id && !stripeZavrnil(v);
  const ZAVRNJENO_BESEDILO = (v) => `Stripe vracila ni izvedel (${v.stripe_stanje}), kupec NI dobil denarja; retry je zavrnjen (409), vrni rocno v Stripu.`;
  const jeTrajna = (e) => ["StripeInvalidRequestError", "StripeIdempotencyError", "StripePermissionError", "StripeAuthenticationError"].includes(e && e.type);

  // Je Stripe nase vracilo ze ustvaril (proces ugasnjen pred zapisom, potekel idempotentni kljuc, vracilo narejeno v prejsnji generaciji kljuca)? Iscemo po metadata.vracilo_id.
  async function najdiNaseVracilo(s, pi, v) {
    const sez = await s.refunds.list({ payment_intent: pi, limit: 100 });
    return (sez.data || []).find((x) => x.metadata && x.metadata.vracilo_id === String(v.id)) || null;
  }
  async function najdiNasoProvizijo(s, feeId, v) {
    const sez = await s.applicationFees.listRefunds(feeId, { limit: 100 });
    return (sez.data || []).find((x) => x.metadata && x.metadata.vracilo_id === String(v.id)) || null;
  }

  // Provizija in Stripova pristojbina naboja za vracilo provizije. Anomalija (brez stripe_fee, razlicne valute) = Rocno, nikoli tiho 0.
  async function izracunajProvizijo(s, pi, v) {
    const p = await s.paymentIntents.retrieve(pi, { expand: ["latest_charge.balance_transaction", "latest_charge.application_fee"] });
    const ch = p.latest_charge && typeof p.latest_charge === "object" ? p.latest_charge : null;
    if (!ch) throw new Error("PaymentIntent brez naboja (charge)");
    const fee = ch.application_fee && typeof ch.application_fee === "object" ? ch.application_fee : null;
    if (!fee) return { feeId: null, vrni: 0, pristojbina: 0 };
    const bt = ch.balance_transaction && typeof ch.balance_transaction === "object" ? ch.balance_transaction : null;
    if (!bt) throw new Error("naboj brez balance_transaction (pristojbine ni mogoce izracunati)");
    const fd = Array.isArray(bt.fee_details) ? bt.fee_details.filter((x) => x.type === "stripe_fee") : [];
    if (!fd.length) throw new Rocno("balance_transaction naboja nima vnosa stripe_fee: vracila provizije ni mogoce izracunati");
    const valute = new Set([fee.currency, ...fd.map((x) => x.currency)].map((x) => String(x || "").toLowerCase()));
    if (valute.size !== 1 || valute.has("")) throw new Rocno(`valuta provizije in Stripove pristojbine se ne ujemata ali manjka (${[...valute].join("/")}): vracila provizije ni mogoce izracunati`);
    const pristojbina = fd.reduce((a, x) => a + (Number(x.amount) || 0), 0);
    // Klub nosi Stripovo pristojbino: od provizije vrnemo SAMO ostanek po odbitku pristojbine (in tisto, kar je bilo ze vrnjeno). Pristojbina > provizija -> 0, razliko nosi Outly.
    return { feeId: fee.id, vrni: Math.max(0, fee.amount - pristojbina - (fee.amount_refunded || 0)), pristojbina };
  }

  async function izvedi(v) {
    const jeEC = v.razlog === "event_cancelled";
    const aOpravljen = !!v.stripe_vracilo_id;   // korak A (vracilo kupcu) je ze narejen: preverb o stanju narocila NE ponavljamo (webhook ga je morda ze oznacil `refunded`)
    const pi = v.payment_intent_id || v.o_pi || null;
    let znesek = v.znesek_cents !== null && v.znesek_cents !== undefined ? v.znesek_cents : (jeEC ? v.total_cents - v.o_refunded : 0);

    // Stripovo vracilo je ze zavrnjeno (failed/canceled), a zapis `ni_uspelo` se ni uspel (proces ugasnjen ali napaka baze) in je sprostitev vrstico vrnila v vrsto:
    // NE uveljavimo narocila in NE vracamo provizije (kupec denarja ni dobil). Enako kot takojsnja zavrnitev: ni_uspelo + alarm, retry 409, panel kaze razlago.
    if (aOpravljen && stripeZavrnil(v)) throw Object.assign(new Error(`vracilo ${v.stripe_vracilo_id} je v stanju ${v.stripe_stanje}`), { type: "StripeInvalidRequestError", code: "refund_" + v.stripe_stanje });

    if (!aOpravljen) {
      // Dogodek je bil med cakanjem obnovljen (zmota lastnika), denar se se ni premaknil: ne vracamo.
      if (jeEC && v.dogodek_status !== "cancelled") {
        await zapri(v.id, "preklicano", "dogodek ni vec odpovedan");
        console.log(`[vracila] preklicano: narocilo ${v.public_ref} (dogodek ni vec odpovedan)`);
        return;
      }
      if (jeEC && !["paid", "partially_refunded", "refunded"].includes(v.o_status)) throw new Rocno(`naroceno je v stanju ${v.o_status}`);
      // Odprt ali izgubljen spor (chargeback) na naroceno: Stripe je znesek ze odtegnil platformi, vracilo kupcu bi ga placalo DVAKRAT. Ne vracamo; po izidu spora admin retry.
      if (v.spor_odprt) throw new Rocno("spor_odprt: na naroceno je odprt ali izgubljen spor (chargeback), vracilo kupcu bi bilo dvojno; pocakaj izid spora (won -> admin retry vracila) ali resi rocno");
      // Brez Stripa: 0 EUR (brezplacno naroceno), testni nacin (PI test_...). Samo stanje.
      if (jeEC && (v.total_cents === 0 || /^test_/.test(pi || ""))) { await opravi(v, v.total_cents === 0 ? 0 : v.total_cents - v.o_refunded, null, true); return; }
    }
    if (!pi) throw new Rocno("naroceno brez PaymentIntenta (placilo ni povezano s Stripom)");
    const s = placila.stripe();
    if (!s) throw new Rocno("STRIPE_SECRET_KEY ni nastavljen, a naroceno ima Stripovo placilo");
    // I36: nikoli klic Stripa z napacnim kljucem (sandbox objekt z zivim kljucem pade z resource_missing, obratno pa bi lahko vrnil tuje placilo).
    const seja = v.checkout_session_id || v.o_seja || "";
    const jeTestno = /^cs_test_/.test(seja) || v.stripe_livemode === false, jeZivo = /^cs_live_/.test(seja) || v.stripe_livemode === true;
    if (placila.jeLive() && jeTestno) throw new Rocno("naroceno je iz sandboxa (cs_test_), Stripe kljuc je ZIV: vrni rocno v Stripovi sandbox nadzorni plosci");
    if (!placila.jeLive() && jeZivo) throw new Rocno("naroceno je iz zivega nacina (cs_live_), Stripe kljuc je SANDBOX: vrni rocno v zivi nadzorni plosci");

    const posvoji = async (re) => {   // vracilo, ki ga je Stripe ze ustvaril (nase): zapisemo ga in nadaljujemo s korakom B
      await pool.query("UPDATE vracila SET stripe_vracilo_id = $2, stripe_stanje = $3 WHERE id = $1", [v.id, re.id, re.status]);
      v.stripe_vracilo_id = re.id; v.stripe_stanje = re.status;
    };
    // Najdeno nase vracilo (crash pred zapisom): zavrnjeno (failed/canceled) -> zapisemo stanje in rocno, korak B (provizija) NE steče.
    const posvojiNaj = async (naj) => {
      await posvoji(naj);
      if (STRIPE_NEDOKONCNO.includes(naj.status)) throw new Rocno(`nase Stripovo vracilo ${naj.id} je v stanju ${naj.status}: kupec NI dobil denarja, vrni rocno v Stripu`);
    };
    // Narocilo je (po Stripu ali v bazi) ze vrnjeno, a NE z nasim vracilom: ročno vracilo v nadzorni plosci. Kupec ima denar, klubu pa vracilo provizije ni naredil nihce.
    const rocnoVrnjeno = async (ostanek) => {
      console.error(`[vracila] POZOR: narocilo ${v.public_ref} je ze v celoti vrnjeno v Stripu (rocno vracilo v nadzorni plosci, ne nase): kupec ima denar, vracilo provizije klubu NI narejeno (Stripe: reverse_transfer ni nujno uporabljen); preveri v Stripu.`);
      await opravi(v, ostanek, "rocno_vrnjeno_v_stripu", false);
    };

    // Korak A: vracilo kupcu. Pred prvim klicem preberemo placilo (ostanek) in ZAMRZNEMO znesek v vrstici (idempotentni kljuc zahteva enake parametre).
    if (!aOpravljen) {
      if (jeEC && v.o_status === "refunded") {
        const naj = await najdiNaseVracilo(s, pi, v);   // vrnjeno z nasim vracilom (crash pred zapisom) ali rocno?
        if (naj) await posvojiNaj(naj);
        else { await rocnoVrnjeno(v.total_cents); return; }
      }
    }
    if (!v.stripe_vracilo_id) {
      if (jeEC && (v.znesek_cents === null || v.znesek_cents === undefined)) {
        const p = await s.paymentIntents.retrieve(pi, { expand: ["latest_charge"] });
        const ch = p.latest_charge && typeof p.latest_charge === "object" ? p.latest_charge : null;
        if (!ch) throw new Error("PaymentIntent brez naboja (charge)");
        if (p.status !== "succeeded") throw new Rocno(`PaymentIntent ni v stanju succeeded (${p.status})`);
        const ostane = ch.amount - (ch.amount_refunded || 0);
        if (ch.amount !== v.total_cents) console.error(`[vracila] POZOR: znesek naboja (${ch.amount} c) != narocilo ${v.public_ref} (${v.total_cents} c); vracam, kar je Stripu ostalo placano (${ostane} c).`);
        if (ostane <= 0) {
          const naj = await najdiNaseVracilo(s, pi, v);
          if (naj) await posvojiNaj(naj); else { await rocnoVrnjeno(Math.max(0, ch.amount_refunded || 0)); return; }
        } else {
          await pool.query("UPDATE vracila SET znesek_cents = $2 WHERE id = $1", [v.id, ostane]);
          v.znesek_cents = ostane; znesek = ostane;
        }
      } else if (v.znesek_cents === null || v.znesek_cents === undefined) {
        await pool.query("UPDATE vracila SET znesek_cents = $2 WHERE id = $1", [v.id, znesek]);
      }
    }
    if (!v.stripe_vracilo_id) {
      if (znesek <= 0) { await opravi(v, 0, "znesek_0", false); return; }
      const meta = { vracilo_id: String(v.id), order_id: String(v.order_id), public_ref: v.public_ref, razlog: v.razlog };
      let re = null;
      try {
        re = await s.refunds.create({ payment_intent: pi, amount: znesek, reverse_transfer: true, refund_application_fee: v.razlog === "inactive_order", metadata: meta },
          { idempotencyKey: kljucA(v) });
      } catch (e) {
        // Vracilo je ze bilo narejeno (proces se je ugasnil pred zapisom, idempotentni kljuc je potekel po 24 h) ali pa je placilo vrnjeno drugje.
        if (e && e.code === "charge_already_refunded") {
          re = await najdiNaseVracilo(s, pi, v);
          if (!re) { await rocnoVrnjeno(znesek); return; }
        } else throw e;
      }
      await posvoji(re);   // Stripovo stanje zapisemo VEDNO, tudi ob takojsnji zavrnitvi (failed/canceled): panel takoj pokaze razlago, ponovi() pa novega vracila ne naredi
      // requires_action NI zavrnitev (Stripe: kupec dobi navodila, vracilo se nadaljuje in lahko uspe): kot pending (uveljaviLokalno, korak B, `potrditev`, izid z webhookom/preverbo).
      if (!["succeeded", "pending", "requires_action"].includes(re.status)) throw Object.assign(new Error(`vracilo ${re.id} je v stanju ${re.status}`), { type: "StripeInvalidRequestError", code: "refund_" + re.status });
    }
    await uveljaviLokalno(v);   // kupec je vrnjen: stanje narocila zapisemo takoj (korak B lahko traja ali pade)

    // Korak B (odpoved dogodka): vracilo provizije brez Stripove pristojbine. Samostojen klic z lastnim idempotentnim kljucem; ob napaki se ponovi samo ta korak.
    if (jeEC) {
      if (v.provizija_za_vrnitev_cents === null || v.provizija_za_vrnitev_cents === undefined) {
        const izr = await izracunajProvizijo(s, pi, v);
        await pool.query("UPDATE vracila SET application_fee_id = $2, provizija_za_vrnitev_cents = $3, stripe_pristojbina_cents = $4 WHERE id = $1", [v.id, izr.feeId, izr.vrni, izr.pristojbina]);
        v.application_fee_id = izr.feeId; v.provizija_za_vrnitev_cents = izr.vrni;
      }
      if (v.application_fee_id && v.provizija_za_vrnitev_cents > 0 && !v.provizija_vracilo_id) {
        let fr = (v.poskusi > 1 || v.kljuc_gen > 0) ? await najdiNasoProvizijo(s, v.application_fee_id, v) : null;   // ponovitev: vracilo provizije je morda ze narejeno (potekel kljuc)
        if (!fr) {
          try {
            fr = await s.applicationFees.createRefund(v.application_fee_id, { amount: v.provizija_za_vrnitev_cents, metadata: { vracilo_id: String(v.id), order_id: String(v.order_id) } },
              { idempotencyKey: kljucB(v) });
          } catch (e) {
            if (!(e && e.type === "StripeInvalidRequestError")) throw e;
            fr = await najdiNasoProvizijo(s, v.application_fee_id, v);   // zavrnjeno, ker je ze narejeno? Ce nasega vracila ni, je napaka prava
            if (!fr) throw e;
          }
        }
        await pool.query("UPDATE vracila SET provizija_vracilo_id = $2 WHERE id = $1", [v.id, fr.id]);
        v.provizija_vracilo_id = fr.id;
      }
    }
    // Zakljucek: `opravljeno` SAMO, ko je Stripe vracilo izvedel (succeeded). `pending` ostane `potrditev` do webhooka (refund.updated / charge.refund.updated) ali preverbe.
    const st = (await pool.query("SELECT stripe_stanje FROM vracila WHERE id = $1", [v.id])).rows[0].stripe_stanje || v.stripe_stanje;
    if (st === "succeeded") { await opravi(v, znesek > 0 ? znesek : (v.znesek_cents || 0), null, false); return; }
    if (st === "pending" || st === "requires_action") {
      await pool.query(`UPDATE vracila SET stanje = 'potrditev', naslednji_poskus_at = NOW() + ($2::bigint * INTERVAL '1 millisecond'), napaka = NULL WHERE id = $1 AND stanje = 'v_teku'`, [v.id, POTRDITEV_MS]);
      console.log(`[vracila] narocilo ${v.public_ref}: Stripe je vracilo sprejel kot ${st}, cakam na izid`);
      return;
    }
    throw Object.assign(new Error(`vracilo ${v.stripe_vracilo_id} je v stanju ${st}`), { type: "StripeInvalidRequestError", code: "refund_" + st });
  }

  // Izid Stripovega vracila (webhook refund.updated | refund.failed | charge.refund.updated ali preverba): succeeded -> opravljeno (mail »vrnili smo«), failed/canceled -> ni_uspelo + alarm.
  // Naroceno ostane `refunded` (Stripe vracilo je bilo sprejeto, denar pa se je vrnil platformi): rocna obravnava.
  async function uskladiVracilo(re) {
    if (!re || !re.id) return;
    const status = String(re.status || "").slice(0, 20);
    // Stripova zavrnitev vrstice, ki je ze v rocno/ni_uspelo: rok za mail kupcu `ni_izvedeno` (#251) steje od zavrnitve, v ISTEM zapisu kot stripe_stanje
    // (obdelovalec mailov sicer vmes vidi `failed` s starim rokom in poslje takoj).
    let r = await pool.query(
      `UPDATE vracila v SET stripe_stanje = $2,
              ni_izvedeno_od_at = CASE WHEN $2 IN ('failed', 'canceled') AND v.stanje IN ('rocno', 'ni_uspelo') AND p.prej IS DISTINCT FROM $2 THEN NOW() ELSE v.ni_izvedeno_od_at END
         FROM (SELECT id, stripe_stanje AS prej FROM vracila WHERE stripe_vracilo_id = $1 FOR UPDATE) p WHERE v.id = p.id RETURNING v.id, v.stanje, p.prej`, [re.id, status]);
    // Webhook je prehitel zapis stripe_vracilo_id (vracilo je ze narejeno, vrstica ga se ne pozna): poisci vrstico po metadata iz SVEZEGA vracila in vracilo posvoji.
    const md = re.metadata || {};
    if (!r.rows.length && /^\d{1,15}$/.test(String(md.vracilo_id || "")) && /^\d{1,15}$/.test(String(md.order_id || ""))) {
      r = await pool.query(`UPDATE vracila SET stripe_vracilo_id = $2, stripe_stanje = $3,
              ni_izvedeno_od_at = CASE WHEN $3 IN ('failed', 'canceled') AND stanje IN ('rocno', 'ni_uspelo') THEN NOW() ELSE ni_izvedeno_od_at END
         WHERE id = $1 AND order_id = $4 AND stripe_vracilo_id IS NULL RETURNING id, stanje`,
        [md.vracilo_id, re.id, status, md.order_id]);
    }
    for (const x of r.rows) {
      if (re.status === "succeeded" && x.stanje === "potrditev") {
        await pool.query("UPDATE vracila SET stanje = 'opravljeno', opravljeno_at = NOW(), napaka = NULL WHERE id = $1 AND stanje = 'potrditev'", [x.id]);
        console.log(`[vracila] opravljeno (Stripe je vracilo izvedel): vracilo ${x.id}`);
      } else if ((re.status === "failed" || re.status === "canceled") && ["rocno", "ni_uspelo"].includes(x.stanje) && ["pending", "requires_action", "succeeded"].includes(x.prej)) {
        // Vrstica je ze v rocni obravnavi/ni_uspelo (stanje ostane), Stripe pa je vracilo pozneje zavrnil: admin mora vedeti, da kupec NI dobil denarja.
        // Rok za mail kupcu `ni_izvedeno` (#251) je ze nastavljen v zgornjem UPDATE (od zavrnitve, ne od prejsnjega vstopa v stanje).
        console.error(`[vracila] POZOR: Stripe vracilo ${re.id} (vracilo ${x.id}) je ${re.status}${re.failure_reason ? ", razlog " + re.failure_reason : ""}: kupec NI dobil denarja (vrstica je ze v stanju ${x.stanje}, stanje ni spremenjeno; prej Stripe: ${x.prej}); retry je zavrnjen (409), vrni rocno v Stripu.`);
      } else if ((re.status === "failed" || re.status === "canceled") && ["potrditev", "opravljeno", "v_teku", "caka"].includes(x.stanje)) {
        await pool.query("UPDATE vracila SET stanje = 'ni_uspelo', napaka = $2, opravljeno_at = NULL, ni_izvedeno_od_at = NOW() WHERE id = $1", [x.id, `Stripe vracilo ${re.id}: ${re.status}${re.failure_reason ? " (" + String(re.failure_reason).slice(0, 60) + ")" : ""}`]);
        console.error(`[vracila] POZOR: Stripe vracilo ${re.id} (vracilo ${x.id}) je ${re.status}${re.failure_reason ? ", razlog " + re.failure_reason : ""}: kupec NI dobil denarja; naroceno je v bazi ze vrnjeno, vrni rocno v Stripu.`);
      }
    }
  }
  // Vracila v stanju `potrditev`, o katerih webhook ni prispel: vprasaj Stripe (najvec 20 na tek).
  async function preveriPotrditve() {
    const s = placila.stripe();
    if (!s) return;
    const r = await pool.query("SELECT id, stripe_vracilo_id, created_at FROM vracila WHERE stanje = 'potrditev' AND naslednji_poskus_at <= NOW() ORDER BY naslednji_poskus_at LIMIT 20");
    for (const x of r.rows) {
      try {
        const re = await s.refunds.retrieve(x.stripe_vracilo_id);
        await uskladiVracilo(re);
        if (re.status === "pending" || re.status === "requires_action") {
          await pool.query("UPDATE vracila SET naslednji_poskus_at = NOW() + ($2::bigint * INTERVAL '1 millisecond') WHERE id = $1 AND stanje = 'potrditev'", [x.id, POTRDITEV_MS]);
          if (Date.now() - new Date(x.created_at).getTime() > 10 * 86400000) console.error(`[vracila] POZOR: Stripe vracilo ${x.stripe_vracilo_id} (vracilo ${x.id}) je ${re.status} ze vec kot 10 dni.`);
        }
      } catch (e) { console.error(`[vracila] preverba vracila ${x.id}:`, e && e.message); }
    }
  }

  async function napaka(v, e) {
    const opis = kratko(e);
    if (e instanceof Rocno) {
      await zapri(v.id, "rocno", opis);
      console.error(`[vracila] POZOR: vracilo narocila ${v.public_ref} (${v.razlog}) zahteva ROCNO obravnavo: ${opis}. ${stripeZavrnil(v) ? ZAVRNJENO_BESEDILO(v) : kupecVrnjen(v) ? "Kupec je vrnjen, dokoncaj vracilo provizije rocno." : "Kupec se NI dobil denarja."}`);
      return;
    }
    if (jeTrajna(e) || v.poskusi >= NAJVEC_POSKUSOV) {
      await zapri(v.id, "ni_uspelo", opis);
      console.error(`[vracila] POZOR: vracilo narocila ${v.public_ref} (${v.razlog}) NI uspelo (poskus ${v.poskusi}/${NAJVEC_POSKUSOV}): ${opis}. ${stripeZavrnil(v) ? ZAVRNJENO_BESEDILO(v) : `${kupecVrnjen(v) ? "Kupec je vrnjen, vracilo provizije ni." : "Kupec se NI dobil denarja."} Ponovi v admin API (POST /admin/api/refunds/${v.id}/retry) ali vrni rocno.`}`);
      return;
    }
    await pool.query(
      `UPDATE vracila SET stanje = 'caka', napaka = $2, naslednji_poskus_at = NOW() + ($3::bigint * INTERVAL '1 millisecond') WHERE id = $1 AND stanje = 'v_teku'`,
      [v.id, opis, premorPoPoskusu(v.poskusi)]);
    console.error(`[vracila] vracilo narocila ${v.public_ref} (${v.razlog}), poskus ${v.poskusi}/${NAJVEC_POSKUSOV} ni uspel, ponovim: ${opis}`);
    if (e && e.type === "StripeRateLimitError") await spi(2000);
  }

  async function obdelaj(id) {
    const r = await pool.query(
      `SELECT v.*, o.public_ref, o.status AS o_status, o.total_cents, o.refunded_cents AS o_refunded, o.stripe_payment_intent_id AS o_pi,
              o.stripe_checkout_session_id AS o_seja, e.status AS dogodek_status,
              EXISTS (SELECT 1 FROM spori sp WHERE sp.order_id = v.order_id AND sp.stanje IN ('needs_response', 'under_review', 'lost')) AS spor_odprt
         FROM vracila v JOIN orders o ON o.id = v.order_id JOIN events e ON e.id = v.event_id WHERE v.id = $1`, [id]);
    const v = r.rows[0];
    if (!v || v.stanje !== "v_teku") return;
    try { await izvedi(v); }
    catch (e) { try { await napaka(v, e); } catch (e2) { console.error("[vracila] zapis napake ni uspel:", e2 && e2.message); } }
  }

  // ---------------------------------------------------------------------------------------------------------------------------
  // IZGUBLJEN SPOR (Martin 12. 10. 2026): povrnitev od kluba. Stripe pri destination chargu spor (znesek + pristojbina spora) bremeni PLATFORMO
  // (docs.stripe.com/connect/destination-charges, »Handle disputes«: povrnitev od kluba s transfer reversal). Terjamo (znesek spora - provizija) + Stripova pristojbina spora
  // (iz dispute.balance_transactions, ne trdo kodirana), omejeno z se neobrnjenim delom transferja (po vracilih z reverse_transfer); razliko nosi Outly (alarm + zapis v vrstici).
  // Sprozi ga SAMO `lost` (webhook nastavi povrnitev_stanje='caka'). Idempotentni kljuc `outly-spor-<id>[-g<n>]`; vrstica nosi zamrznjene vrednosti in reversal_id.
  // ---------------------------------------------------------------------------------------------------------------------------
  const kljucSpor = (sp) => `outly-spor-${sp.id}${sp.povrnitev_kljuc_gen ? "-g" + sp.povrnitev_kljuc_gen : ""}`;
  async function izvediSpor(sp) {
    const s = placila.stripe();
    if (!s) throw new Rocno("STRIPE_SECRET_KEY ni nastavljen");
    if (sp.stanje !== "lost") throw new Rocno(`spor ni izgubljen (${sp.stanje})`);
    if (sp.order_id === null) throw new Rocno("spor brez narocila: povrnitve od kluba ni mogoce izracunati");
    const dp = await s.disputes.retrieve(sp.id);
    if (dp.status !== "lost") throw new Rocno(`Stripe poroca stanje spora ${dp.status}, ne lost`);
    const chId = typeof dp.charge === "string" ? dp.charge : dp.charge && dp.charge.id;
    if (!chId) throw new Rocno("spor brez naboja");
    const ch = await s.charges.retrieve(chId, { expand: ["application_fee"] });
    const trId = typeof ch.transfer === "string" ? ch.transfer : ch.transfer && ch.transfer.id;
    if (!trId) throw new Rocno("naboj nima transferja (ni destination charge?): povrnitve od kluba ni mogoce izracunati");
    // Ponovitev: reversal je morda ze narejen (potekel kljuc, crash pred zapisom). Najprej ga poisci in posvoji z NJEGOVIM zneskom (ne ponovno izracunanim: transfer ima ta reversal ze v amount_reversed).
    let rev = null;
    if (!sp.reversal_id && (sp.povrnitev_poskusi > 1 || sp.povrnitev_kljuc_gen > 0)) {
      rev = ((await s.transfers.listReversals(trId, { limit: 100 })).data || []).find((x) => x.metadata && x.metadata.spor_id === sp.id) || null;
    }
    // Zamrznjene vrednosti (prvi poskus): zelena = (znesek spora - sorazmerni del provizije) + Stripova pristojbina spora; dejansko = min(zelena, neobrnjeni del transferja).
    if (sp.povrnitev_zelena_cents === null || sp.povrnitev_zelena_cents === undefined) {
      const fee = ch.application_fee && typeof ch.application_fee === "object" ? ch.application_fee : null;
      const bts = Array.isArray(dp.balance_transactions) ? dp.balance_transactions : [];
      const valute = new Set([dp.currency, ...bts.map((x) => x.currency)].map((x) => String(x || "").toLowerCase()));
      if (valute.size !== 1 || valute.has("")) throw new Rocno(`valuta spora in njegovih balance_transactions se ne ujema ali manjka (${[...valute].join("/")})`);
      if (!bts.length) throw new Rocno("spor nima balance_transactions: Stripove pristojbine spora ni mogoce prebrati");
      const pristojbina = bts.reduce((a, x) => a + (Number(x.fee) || 0), 0);
      const delProvizije = fee && ch.amount > 0 ? Math.round(fee.amount * dp.amount / ch.amount) : 0;
      const zelena = Math.max(0, dp.amount - delProvizije) + pristojbina;
      let vrni;
      if (rev) vrni = rev.amount;
      else { const tr0 = await s.transfers.retrieve(trId); vrni = Math.min(zelena, Math.max(0, (tr0.amount || 0) - (tr0.amount_reversed || 0))); }
      await pool.query("UPDATE spori SET povrnitev_zelena_cents = $2, povrnitev_cents = $3, pristojbina_spora_cents = $4 WHERE id = $1", [sp.id, zelena, vrni, pristojbina]);
      sp.povrnitev_zelena_cents = zelena; sp.povrnitev_cents = vrni; sp.pristojbina_spora_cents = pristojbina;
    }
    if (rev) {
      await pool.query("UPDATE spori SET reversal_id = $2, povrnitev_cents = $3 WHERE id = $1", [sp.id, rev.id, rev.amount]);
      sp.reversal_id = rev.id; sp.povrnitev_cents = rev.amount;
    } else if (sp.povrnitev_cents > 0 && !sp.reversal_id) {
      const nov = await s.transfers.createReversal(trId, { amount: sp.povrnitev_cents, metadata: { spor_id: sp.id, order_id: String(sp.order_id || "") } }, { idempotencyKey: kljucSpor(sp) });
      await pool.query("UPDATE spori SET reversal_id = $2 WHERE id = $1", [sp.id, nov.id]);
      sp.reversal_id = nov.id;
    }
    const manjka = Math.max(0, sp.povrnitev_zelena_cents - sp.povrnitev_cents);
    await pool.query("UPDATE spori SET povrnitev_stanje = 'opravljeno', povrnitev_napaka = $2 WHERE id = $1 AND povrnitev_stanje = 'v_teku'",
      [sp.id, manjka > 0 ? `neobrnjeni del transferja ne zadosti: ${manjka} c nosi Outly` : null]);
    console.log(`[spori] povrnitev od kluba opravljena: spor ${sp.id}, ${sp.povrnitev_cents} c (zelena ${sp.povrnitev_zelena_cents} c, pristojbina spora ${sp.pristojbina_spora_cents} c)`);
    if (manjka > 0) console.error(`[spori] POZOR: spor ${sp.id}: od kluba je mogoce povrniti samo ${sp.povrnitev_cents} c od ${sp.povrnitev_zelena_cents} c (transfer je ze obrnjen, npr. vracilo); ${manjka} c nosi Outly.`);
  }
  async function napakaSpor(sp, e) {
    const opis = kratko(e);
    if (e instanceof Rocno) {
      await pool.query("UPDATE spori SET povrnitev_stanje = 'rocno', povrnitev_napaka = $2 WHERE id = $1 AND povrnitev_stanje = 'v_teku'", [sp.id, opis]);
      console.error(`[spori] POZOR: povrnitev od kluba za izgubljen spor ${sp.id} zahteva ROCNO obravnavo: ${opis}. Denar ni terjan od kluba.`);
      return;
    }
    if (jeTrajna(e) || sp.povrnitev_poskusi >= NAJVEC_POSKUSOV) {
      await pool.query("UPDATE spori SET povrnitev_stanje = 'ni_uspelo', povrnitev_napaka = $2 WHERE id = $1 AND povrnitev_stanje = 'v_teku'", [sp.id, opis]);
      console.error(`[spori] POZOR: povrnitev od kluba za izgubljen spor ${sp.id} NI uspela (poskus ${sp.povrnitev_poskusi}/${NAJVEC_POSKUSOV}): ${opis}. Izgubo trenutno nosi Outly; ponovi v admin API (POST /admin/api/disputes/${sp.id}/retry).`);
      return;
    }
    await pool.query("UPDATE spori SET povrnitev_stanje = 'caka', povrnitev_napaka = $2, povrnitev_naslednji_at = NOW() + ($3::bigint * INTERVAL '1 millisecond') WHERE id = $1 AND povrnitev_stanje = 'v_teku'",
      [sp.id, opis, premorPoPoskusu(sp.povrnitev_poskusi)]);
    console.error(`[spori] povrnitev od kluba za spor ${sp.id}, poskus ${sp.povrnitev_poskusi}/${NAJVEC_POSKUSOV} ni uspela, ponovim: ${opis}`);
  }
  async function obdelajSpore() {
    const r = await pool.query(
      `UPDATE spori SET povrnitev_stanje = 'v_teku', povrnitev_prevzeto_at = NOW(), povrnitev_poskusi = povrnitev_poskusi + 1
        WHERE id IN (SELECT id FROM spori WHERE povrnitev_stanje = 'caka' AND povrnitev_naslednji_at <= NOW() ORDER BY povrnitev_naslednji_at LIMIT 5 FOR UPDATE SKIP LOCKED)
        RETURNING *`);
    for (const sp of r.rows) {
      try { await izvediSpor(sp); } catch (e) { try { await napakaSpor(sp, e); } catch (e2) { console.error("[spori] zapis napake ni uspel:", e2 && e2.message); } }
      if (RAZMAK_MS) await spi(RAZMAK_MS);
    }
    // Zastarelo prevzeto (proces ugasnjen med povrnitvijo): nazaj v vrsto, idempotentni kljuc prepreci dvojno povrnitev.
    await pool.query("UPDATE spori SET povrnitev_stanje = 'caka', povrnitev_naslednji_at = NOW() WHERE povrnitev_stanje = 'v_teku' AND povrnitev_prevzeto_at < NOW() - ($1::int * INTERVAL '1 minute')", [ZASTARELO_MIN]);
  }
  // Admin: povrnitev ni_uspelo / rocno znova (nova generacija kljuca, zamrznjene vrednosti se izracunajo znova; ze narejen reversal se najde po metadata.spor_id).
  async function ponoviSpor(id) {
    const u = await pool.query(
      `UPDATE spori SET povrnitev_stanje = 'caka', povrnitev_poskusi = 0, povrnitev_naslednji_at = NOW(), povrnitev_napaka = NULL, povrnitev_kljuc_gen = povrnitev_kljuc_gen + 1,
              povrnitev_zelena_cents = CASE WHEN reversal_id IS NULL THEN NULL ELSE povrnitev_zelena_cents END, povrnitev_cents = CASE WHEN reversal_id IS NULL THEN NULL ELSE povrnitev_cents END
        WHERE id = $1 AND povrnitev_stanje IN ('ni_uspelo','rocno') RETURNING id`, [id]);
    if (u.rowCount) zbudi();
    return u.rowCount > 0;
  }

  let tece = false;
  async function tek() {
    if (tece) return;
    tece = true;
    try {
      await pomeni();
      await sprostiZastarele();
      const konec = Date.now() + PRORACUN_MS;
      for (;;) {
        const ids = await prevzemi(PAKET);
        if (!ids.length) break;
        for (const id of ids) { await obdelaj(id); if (RAZMAK_MS) await spi(RAZMAK_MS); }
        if (Date.now() > konec) break;
      }
      await preveriPotrditve();
      await obdelajSpore();
      if (posljiNeposlane) await posljiNeposlane();
    } catch (e) { console.error("[vracila] tek:", e && e.message); }
    finally { tece = false; }
  }

  function zazeni() {
    if (TICK_MS > 0) setInterval(() => { tek(); }, TICK_MS).unref();
  }
  const zbudi = () => { if (TICK_MS > 0) setTimeout(() => { tek(); }, 50).unref(); };

  // Tik PRED mailom kupcu `ni_izvedeno` (#251, pregled PR #261): je kupec denar medtem vseeno dobil? Po alarmu »vrni rocno v Stripu« admin vrne v Stripovi
  // nadzorni plosci (novo vracilo brez nasega metadata.vracilo_id, uskladiVracilo ga ne poveze), vrstica pa ostane ni_uspelo/failed.
  // Vsota USPELIH vracil (succeeded) na PaymentIntentu >= placano (event_cancelled: total narocila; inactive_order: znesek vrstice) -> vrstico zapremo kot
  // rocno vrnjeno (ista pot kot rocnoVrnjeno v izvedi(): opravi(... 'rocno_vrnjeno_v_stripu'), kupec dobi »vrnili smo«) in maila `ni_izvedeno` NE posljemo.
  // Vrne: 'poslji' (kupec res ni vrnjen) | 'vrnjeno' (vrstica zaprta) | 'ne' (trajno ne posiljaj: brez kljuca, drug nacin I36, testno, vrstica ni vec v stanju)
  //       | 'preskoci' (vrstica medtem ni vec v ni_uspelo/rocno) | 'neznano' (Stripe ni dosegljiv / napaka: ta obhod NE posiljaj, poskusi pozneje; raje zamuda kot napacen mail).
  async function kupecVrnjenPredMailom(id) {
    const r = await pool.query(
      `SELECT v.*, o.public_ref, o.total_cents, o.stripe_payment_intent_id AS o_pi, o.stripe_checkout_session_id AS o_seja
         FROM vracila v JOIN orders o ON o.id = v.order_id WHERE v.id = $1`, [id]);
    const v = r.rows[0];
    if (!v || !["ni_uspelo", "rocno"].includes(v.stanje)) return "preskoci";   // vrstica je medtem drugje (retry, webhook): mail ne velja vec, poskusov ne zakljenemo
    const pi = v.payment_intent_id || v.o_pi || null;
    const s = placila.stripe();
    if (!pi || /^test_/.test(pi) || !s) return "ne";
    const seja = v.checkout_session_id || v.o_seja || "";
    const jeTestno = /^cs_test_/.test(seja) || v.stripe_livemode === false, jeZivo = /^cs_live_/.test(seja) || v.stripe_livemode === true;
    if ((placila.jeLive() && jeTestno) || (!placila.jeLive() && jeZivo)) return "ne";   // I36: nikoli klic Stripa z napacnim kljucem
    let sez;
    try { sez = await s.refunds.list({ payment_intent: pi, limit: 100 }); }
    catch (e) { console.error(`[vracila] preverba pred mailom ni_izvedeno (vracilo ${id}): Stripe ni odgovoril (${kratko(e)}), mail odlozen`); return "neznano"; }
    const vrnjeno = (sez.data || []).filter((x) => x.status === "succeeded").reduce((a, x) => a + (Number(x.amount) || 0), 0);
    const placano = v.razlog === "event_cancelled" ? v.total_cents : (v.znesek_cents || 0);
    if (placano <= 0 || vrnjeno < placano) return "poslji";
    const z = await pool.query("UPDATE vracila SET ni_izvedeno_od_at = NULL WHERE id = $1 AND stanje IN ('ni_uspelo', 'rocno') RETURNING id", [id]);
    if (!z.rowCount) return "preskoci";
    console.error(`[vracila] POZOR: narocilo ${v.public_ref}: nase vracilo je Stripe zavrnil, a je placilo v Stripu ze v celoti vrnjeno (${vrnjeno} c, rocno vracilo v nadzorni plosci): vrstica zaprta kot rocno_vrnjeno_v_stripu, mail »se ni izvedeno« NI poslan; vracilo provizije klubu preveri rocno.`);
    await opravi(v, v.znesek_cents !== null && v.znesek_cents !== undefined ? v.znesek_cents : vrnjeno, "rocno_vrnjeno_v_stripu", false);
    return "vrnjeno";
  }

  // Admin: vracilo v stanju ni_uspelo / rocno ponovno v vrsto (po popravku vzroka). Vrne true, ce je bilo kaj ponovljeno.
  // Idempotentni kljuc ima isti odgovor 24 h (tudi napako), zato ponovitev POVECA GENERACIJO kljuca in zamrznjene vrednosti (znesek, provizija) izracuna znova.
  // Prej preveri pri Stripu, da nasega vracila (metadata.vracilo_id) se ni: ce obstaja, ga posvoji (nikoli drugo vracilo istemu naroceno).
  async function ponovi(id) {
    const r = await pool.query(
      `SELECT v.*, o.stripe_payment_intent_id AS o_pi FROM vracila v JOIN orders o ON o.id = v.order_id WHERE v.id = $1 AND v.stanje IN ('ni_uspelo','rocno')`, [id]);
    const v = r.rows[0];
    if (!v) return false;
    // Stripe je vracilo zavrnil (failed/canceled): novo vracilo bi lahko bilo dvojno, rocno v Stripu. Panel gumba tedaj ne ponuja (STRIPE_ZAVRNJENO v admin/index.html).
    if (STRIPE_NEDOKONCNO.includes(v.stripe_stanje)) return false;
    let najdeno = null;
    const pi = v.payment_intent_id || v.o_pi;
    const s = placila.stripe();
    if (!v.stripe_vracilo_id && s && pi && !/^test_/.test(pi)) najdeno = await najdiNaseVracilo(s, pi, v);
    // Nase vracilo pri Stripu ze obstaja in je zavrnjeno (vrstica tega ni vedela: zapis ni uspel ali je starejsa): zapisemo stanje in NE posvojimo v novo vrsto
    // (sicer bi izvedi() z aOpravljen oznacil naroceno `refunded`, kupec pa denarja ni dobil). Admin dobi 409 in rocno razlago.
    if (najdeno && STRIPE_NEDOKONCNO.includes(najdeno.status)) {
      await pool.query(`UPDATE vracila SET stripe_vracilo_id = COALESCE(stripe_vracilo_id, $2), stripe_stanje = $3,
              ni_izvedeno_od_at = CASE WHEN stripe_stanje IS DISTINCT FROM $3 THEN NOW() ELSE ni_izvedeno_od_at END WHERE id = $1`, [id, najdeno.id, najdeno.status]);
      return false;
    }
    const u = await pool.query(
      `UPDATE vracila SET stanje = 'caka', poskusi = 0, naslednji_poskus_at = NOW(), napaka = NULL, kljuc_gen = kljuc_gen + 1, ni_izvedeno_od_at = NULL,
              stripe_vracilo_id = COALESCE(stripe_vracilo_id, $2), stripe_stanje = COALESCE($3, stripe_stanje),
              znesek_cents = CASE WHEN razlog = 'event_cancelled' AND stripe_vracilo_id IS NULL AND $2::text IS NULL THEN NULL ELSE znesek_cents END,
              application_fee_id = NULL, provizija_za_vrnitev_cents = CASE WHEN provizija_vracilo_id IS NOT NULL THEN provizija_za_vrnitev_cents ELSE NULL END,
              stripe_pristojbina_cents = CASE WHEN provizija_vracilo_id IS NOT NULL THEN stripe_pristojbina_cents ELSE NULL END
        WHERE id = $1 AND stanje IN ('ni_uspelo','rocno') RETURNING id`, [id, najdeno ? najdeno.id : null, najdeno ? najdeno.status : null]);
    if (u.rowCount) zbudi();
    return u.rowCount > 0;
  }

  return { vrstiZaDogodek, pomeni, tek, zazeni, zbudi, ponovi, ponoviSpor, uskladiVracilo, kupecVrnjenPredMailom };
}

module.exports = { ustvari };
