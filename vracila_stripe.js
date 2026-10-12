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
// Stanja: caka -> v_teku -> opravljeno | ni_uspelo (alarm, admin ponovi) | rocno (alarm; drug nacin Stripa, brez kljuca, nepricakovano stanje) | preklicano.
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
  const PRORACUN_MS = 45000;                                           // najdlje en tek (potem mail in nov tek)
  const ZASTARELO_MIN = 10;                                            // prevzeto vracilo brez zakljucka (proces ugasnjen) se vrne v vrsto

  const premorPoPoskusu = (poskusi) => (PREMOR_MS > 0 ? PREMOR_MS : PREMORI_MS[Math.min(Math.max(poskusi, 1), PREMORI_MS.length) - 1]);

  // Odpoved dogodka: vstavi vrstice za VSA placana narocila dogodka (en stavek, brez Stripa; guest lista ni prodaja). c = povezava klicatelja (transakcija odpovedi) ali pool.
  async function vrstiZaDogodek(c, eventId, zamikS = ZAMIK_S) {
    // Izrecna odpoved (tudi ze odpovedanega dogodka, ki ga sprozilec ni zabelezil): dogodek odslej spremlja sweep (placilo, ki prispe po odpovedi).
    await c.query("INSERT INTO odpovedi_dogodkov (event_id) VALUES ($1) ON CONFLICT (event_id) DO NOTHING", [eventId]);
    const r = await c.query(
      `INSERT INTO vracila (order_id, event_id, razlog, naslednji_poskus_at)
       SELECT o.id, o.event_id, 'event_cancelled', NOW() + ($2::int * INTERVAL '1 second')
         FROM orders o WHERE o.event_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL
       ON CONFLICT (order_id, razlog) DO NOTHING`, [eventId, zamikS]);
    return r.rowCount;
  }

  // Varovalka: dogodek odpovedan po drugi poti (PUT /events/:id, admin, SQL) ali placilo, ki je prispelo po odpovedi, nista ostala brez vracila.
  // SAMO dogodki iz `odpovedi_dogodkov` (odpovedani po migraciji 047): starejsih odpovedanih dogodkov sweep ne dotakne.
  let zadnjiSweep = 0;
  async function pomeni() {
    if (SWEEP_MS <= 0 || Date.now() - zadnjiSweep < SWEEP_MS) return 0;
    zadnjiSweep = Date.now();
    const r = await pool.query(
      `INSERT INTO vracila (order_id, event_id, razlog, naslednji_poskus_at)
       SELECT o.id, o.event_id, 'event_cancelled', NOW() + ($1::int * INTERVAL '1 second')
         FROM odpovedi_dogodkov od JOIN events e ON e.id = od.event_id AND e.status = 'cancelled'
         JOIN orders o ON o.event_id = e.id AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL
        WHERE NOT EXISTS (SELECT 1 FROM vracila v WHERE v.order_id = o.id AND v.razlog = 'event_cancelled')
        LIMIT 2000
       ON CONFLICT (order_id, razlog) DO NOTHING`, [ZAMIK_S]);
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
    `UPDATE vracila SET stanje = $2, napaka = $3, opravljeno_at = CASE WHEN $2 = 'opravljeno' THEN NOW() ELSE opravljeno_at END WHERE id = $1 AND stanje = 'v_teku'`, [id, stanje, napaka || null]);

  // Lokalno stanje po uspesnem vracilu (isto kot webhook charge.refunded: placila.uveljaviVracilo) + zakljucek vrstice, v ENI transakciji.
  async function opravi(v, znesek, opomba, brezStripa) {   // brezStripa: samo stanje (0 EUR, testni nacin)
    await vTransakciji(async (c) => {
      const o = (await c.query("SELECT id, public_ref, total_cents, refunded_cents, status FROM orders WHERE id = $1 FOR UPDATE", [v.order_id])).rows[0];
      if (v.razlog === "event_cancelled" && o && ["paid", "partially_refunded", "refunded"].includes(o.status)) {
        // Odpoved dogodka vrne VSE (kupec dobi celoten znesek): naroceno je po vracilu v celoti vrnjeno (webhook charge.refunded je morda zapis ze naredil; zapis nikoli ne gre navzdol).
        await placila.uveljaviVracilo(c, o, o.total_cents, null);
      }
      await c.query(
        `UPDATE vracila SET stanje = 'opravljeno', opravljeno_at = NOW(), napaka = $2, znesek_cents = $3, brez_stripa = $4 WHERE id = $1`,
        [v.id, opomba || null, znesek, !!brezStripa]);
    });
    console.log(`[vracila] opravljeno: narocilo ${v.public_ref} (${v.razlog}), ${znesek} c${brezStripa ? ", brez Stripa" : ""}${opomba ? " [" + opomba + "]" : ""}`);
    if (naKoncano) { try { Promise.resolve(naKoncano(v.id)).catch((e) => console.error("[vracila] obvestilo:", e && e.message)); } catch (e) { console.error("[vracila] obvestilo:", e && e.message); } }
  }

  // Stripov napaka: trajna (ponovitev ne pomaga) ali prehodna (omrezje, 5xx, omejitev hitrosti).
  const jeTrajna = (e) => ["StripeInvalidRequestError", "StripeIdempotencyError", "StripePermissionError", "StripeAuthenticationError"].includes(e && e.type);

  async function izvedi(v) {
    // Dogodek je bil med cakanjem obnovljen (zmota lastnika), denar se se ni premaknil: ne vracamo.
    if (v.razlog === "event_cancelled" && v.dogodek_status !== "cancelled" && !v.stripe_vracilo_id) {
      await zapri(v.id, "preklicano", "dogodek ni vec odpovedan");
      console.log(`[vracila] preklicano: narocilo ${v.public_ref} (dogodek ni vec odpovedan)`);
      return;
    }
    if (v.razlog === "event_cancelled") {
      if (v.o_status === "refunded") { await zapri(v.id, "opravljeno", "ze_vrnjeno"); return; }   // vrnjeno prej (nadzorna plosca): nic za storiti
      if (!["paid", "partially_refunded"].includes(v.o_status)) throw new Rocno(`naroceno je v stanju ${v.o_status}`);
    }
    const pi = v.payment_intent_id || v.o_pi || null;
    let znesek = v.znesek_cents !== null && v.znesek_cents !== undefined ? v.znesek_cents : (v.razlog === "event_cancelled" ? v.total_cents - v.o_refunded : 0);

    // Brez Stripa: 0 EUR (brezplacno naroceno), testni nacin (PI test_...). Samo stanje.
    if (v.razlog === "event_cancelled" && (v.total_cents === 0 || /^test_/.test(pi || ""))) { await opravi(v, v.total_cents === 0 ? 0 : v.total_cents - v.o_refunded, null, true); return; }
    if (!pi) throw new Rocno("naroceno brez PaymentIntenta (placilo ni povezano s Stripom)");

    const s = placila.stripe();
    if (!s) throw new Rocno("STRIPE_SECRET_KEY ni nastavljen, a naroceno ima Stripovo placilo");
    // I36: nikoli klic Stripa z napacnim kljucem (sandbox objekt z zivim kljucem pade z resource_missing, obratno pa bi lahko vrnil tuje placilo).
    const seja = v.checkout_session_id || v.o_seja || "";
    const jeTestno = /^cs_test_/.test(seja) || v.stripe_livemode === false, jeZivo = /^cs_live_/.test(seja) || v.stripe_livemode === true;
    if (placila.jeLive() && jeTestno) throw new Rocno("naroceno je iz sandboxa (cs_test_), Stripe kljuc je ZIV: vrni rocno v Stripovi sandbox nadzorni plosci");
    if (!placila.jeLive() && jeZivo) throw new Rocno("naroceno je iz zivega nacina (cs_live_), Stripe kljuc je SANDBOX: vrni rocno v zivi nadzorni plosci");

    // Korak A: vracilo kupcu. Pred prvim klicem preberemo placilo (ostanek, provizija, Stripova pristojbina) in ZAMRZNEMO znesek v vrstici (idempotentni kljuc zahteva enake parametre).
    if (!v.stripe_vracilo_id) {
      // stripe_pristojbina_cents je zapisan skupaj z zneskom (isti UPDATE): NULL = branja se ni bilo.
      if (v.razlog === "event_cancelled" && (v.stripe_pristojbina_cents === null || v.stripe_pristojbina_cents === undefined)) {
        const p = await s.paymentIntents.retrieve(pi, { expand: ["latest_charge.balance_transaction", "latest_charge.application_fee"] });
        const ch = p.latest_charge && typeof p.latest_charge === "object" ? p.latest_charge : null;
        if (!ch) throw new Error("PaymentIntent brez naboja (charge)");
        if (p.status !== "succeeded") throw new Rocno(`PaymentIntent ni v stanju succeeded (${p.status})`);
        const ostane = ch.amount - (ch.amount_refunded || 0);
        if (ch.amount !== v.total_cents) console.error(`[vracila] POZOR: znesek naboja (${ch.amount} c) != narocilo ${v.public_ref} (${v.total_cents} c); vracam, kar je Stripu ostalo placano (${ostane} c).`);
        if (ostane <= 0) { await opravi(v, Math.max(0, ch.amount_refunded || 0), "ze_vrnjeno_v_stripu", false); return; }
        const bt = ch.balance_transaction && typeof ch.balance_transaction === "object" ? ch.balance_transaction : null;
        if (!bt) throw new Error("naboj brez balance_transaction (pristojbine ni mogoce izracunati)");
        const fd = Array.isArray(bt.fee_details) ? bt.fee_details.filter((x) => x.type === "stripe_fee") : null;
        const pristojbina = fd ? fd.reduce((a, x) => a + (Number(x.amount) || 0), 0) : (Number(bt.fee) || 0);
        const fee = ch.application_fee && typeof ch.application_fee === "object" ? ch.application_fee : null;
        // Klub nosi Stripovo pristojbino: od provizije vrnemo SAMO ostanek po odbitku pristojbine (in tisto, kar je bilo ze vrnjeno). Pristojbina > provizija -> 0, razliko nosi Outly.
        const provizijaVrni = fee ? Math.max(0, fee.amount - pristojbina - (fee.amount_refunded || 0)) : 0;
        await pool.query(
          `UPDATE vracila SET znesek_cents = $2, application_fee_id = $3, provizija_za_vrnitev_cents = $4, stripe_pristojbina_cents = $5 WHERE id = $1`,
          [v.id, ostane, fee ? fee.id : null, provizijaVrni, pristojbina]);
        v.znesek_cents = ostane; v.application_fee_id = fee ? fee.id : null; v.provizija_za_vrnitev_cents = provizijaVrni;
        znesek = ostane;
      } else if (v.znesek_cents === null || v.znesek_cents === undefined) {
        await pool.query("UPDATE vracila SET znesek_cents = $2 WHERE id = $1", [v.id, znesek]);
      }
      if (znesek <= 0) { await opravi(v, 0, "znesek_0", false); return; }
      const meta = { vracilo_id: String(v.id), order_id: String(v.order_id), public_ref: v.public_ref, razlog: v.razlog };
      let re = null;
      try {
        re = await s.refunds.create({ payment_intent: pi, amount: znesek, reverse_transfer: true, refund_application_fee: v.razlog === "inactive_order", metadata: meta },
          { idempotencyKey: `outly-vracilo-${v.id}` });
      } catch (e) {
        // Vracilo je ze bilo narejeno (proces se je ugasnil pred zapisom, idempotentni kljuc je potekel po 24 h) ali pa je placilo vrnjeno drugje.
        if (e && e.code === "charge_already_refunded") {
          const sez = await s.refunds.list({ payment_intent: pi, limit: 100 });
          re = (sez.data || []).find((x) => x.metadata && x.metadata.vracilo_id === String(v.id)) || null;
          if (!re) { await opravi(v, znesek, "ze_vrnjeno_v_stripu", false); return; }
        } else throw e;
      }
      if (!["succeeded", "pending"].includes(re.status)) throw Object.assign(new Error(`vracilo ${re.id} je v stanju ${re.status}`), { type: "StripeInvalidRequestError", code: "refund_" + re.status });
      await pool.query("UPDATE vracila SET stripe_vracilo_id = $2 WHERE id = $1", [v.id, re.id]);
      v.stripe_vracilo_id = re.id;
    }

    // Korak B (odpoved dogodka): vracilo provizije brez Stripove pristojbine. Samostojen klic z lastnim idempotentnim kljucem; ob napaki se ponovi samo ta korak.
    if (v.razlog === "event_cancelled" && v.application_fee_id && v.provizija_za_vrnitev_cents > 0 && !v.provizija_vracilo_id) {
      try {
        const fr = await s.applicationFees.createRefund(v.application_fee_id, { amount: v.provizija_za_vrnitev_cents, metadata: { vracilo_id: String(v.id), order_id: String(v.order_id) } },
          { idempotencyKey: `outly-vracilo-${v.id}-provizija` });
        await pool.query("UPDATE vracila SET provizija_vracilo_id = $2 WHERE id = $1", [v.id, fr.id]);
        v.provizija_vracilo_id = fr.id;
      } catch (e) {
        if (!(e && e.code === "application_fee_already_refunded")) throw e;   // provizija je ze vrnjena (npr. prejsnji poskus): nadaljuj
      }
    }
    await opravi(v, znesek, null, false);
  }

  async function napaka(v, e) {
    const opis = kratko(e);
    if (e instanceof Rocno) {
      await zapri(v.id, "rocno", opis);
      console.error(`[vracila] POZOR: vracilo narocila ${v.public_ref} (${v.razlog}) zahteva ROCNO obravnavo: ${opis}. Kupec se NI dobil denarja.`);
      return;
    }
    if (jeTrajna(e) || v.poskusi >= NAJVEC_POSKUSOV) {
      await zapri(v.id, "ni_uspelo", opis);
      console.error(`[vracila] POZOR: vracilo narocila ${v.public_ref} (${v.razlog}) NI uspelo (poskus ${v.poskusi}/${NAJVEC_POSKUSOV}): ${opis}. Kupec se NI dobil denarja; ponovi v admin API (POST /admin/api/refunds/${v.id}/retry) ali vrni rocno.`);
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
              o.stripe_checkout_session_id AS o_seja, e.status AS dogodek_status
         FROM vracila v JOIN orders o ON o.id = v.order_id JOIN events e ON e.id = v.event_id WHERE v.id = $1`, [id]);
    const v = r.rows[0];
    if (!v || v.stanje !== "v_teku") return;
    try { await izvedi(v); }
    catch (e) { try { await napaka(v, e); } catch (e2) { console.error("[vracila] zapis napake ni uspel:", e2 && e2.message); } }
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
      if (posljiNeposlane) await posljiNeposlane();
    } catch (e) { console.error("[vracila] tek:", e && e.message); }
    finally { tece = false; }
  }

  function zazeni() {
    if (TICK_MS > 0) setInterval(() => { tek(); }, TICK_MS).unref();
  }
  const zbudi = () => { if (TICK_MS > 0) setTimeout(() => { tek(); }, 50).unref(); };

  // Admin: vracilo v stanju ni_uspelo / rocno ponovno v vrsto (po popravku vzroka). Vrne true, ce je bilo kaj ponovljeno.
  async function ponovi(id) {
    const r = await pool.query(
      `UPDATE vracila SET stanje = 'caka', poskusi = 0, naslednji_poskus_at = NOW(), napaka = NULL WHERE id = $1 AND stanje IN ('ni_uspelo','rocno') RETURNING id`, [id]);
    if (r.rowCount) zbudi();
    return r.rowCount > 0;
  }

  return { vrstiZaDogodek, pomeni, tek, zazeni, zbudi, ponovi };
}

module.exports = { ustvari };
