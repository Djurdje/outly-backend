// Stripe Checkout + Connect Express (issue #19).
//
// Model (DECISIONS 2026-09): prodajalec je KLUB, Outly je posrednik s provizijo. Tehnicno: destination charge
// (transfer_data.destination = racun kluba) z application_fee_amount (provizija) in on_behalf_of = racun kluba,
// da je klub tudi »business of record« (pravna analiza 1. 10. 2026, V1: brez on_behalf_of bi bil to Outly).
// IZJEMA (I50, Martin v seji menedzerja 19. 10. 2026): dogodek, katerega prodajalec (events.club_id) ima clubs.is_official = TRUE, prodaja NEXT DIMENSIONS sam
// (platforma): Checkout seja BREZ transfer_data, BREZ on_behalf_of, BREZ application_fee_amount (placilo gre neposredno na platformni racun), provizija naroclila 0,
// racun kluba (stripe_account_id, stripe_charges_enabled) ni pogoj, nacin placila doloca samo platformni kljuc. Vracila brez reverse_transfer in brez vracila provizije
// (vracila_stripe.js), spor ne bremeni nobenega kluba (spor() spodaj). VSAKO naroclilo take prodaje (tudi 0 EUR in testni nacin) nosi orders.stripe_account_id = PLATFORMNI_RACUN
// (»platform«; izrecna oznaka PRODAJALCA, zamrznjena ob nakupu, NE NULL: NULL ima testni in brezplacni nakup navadnega kluba). Ali je denar sel skozi Stripe, oznaka NE pove:
// to odlocata total_cents = 0 in PI `test_` (vracila, finance, maili), kot pri navadnem klubu.
// Kartica se nikoli ne vnasa v nas vmesnik: kupec placa na Stripovi gostovani strani (Checkout).
//
// Tok nakupa:
//   1. POST /events/:id/orders (ali miza) v transakciji ustvari narocilo `pending` (zaloga rezervirana, vstopnic se ni).
//   2. Po COMMIT-u ustvari Checkout sejo (idempotentni kljuc = id narocila) in vrne checkout_url.
//   3. Kupec placa -> webhook checkout.session.completed -> narocilo `paid`, nastanejo vstopnice.
//   4. Seja poteče ali placilo pade -> webhook -> `cancelled`/`failed`, sprozilec sprosti zalogo.
//   5. Pospravljalec (vsakih 5 min) preveri pri Stripu narocila, ki cakajo predolgo (izgubljen webhook).
//
// Nacin placila (nacinPlacila):
//   - brez STRIPE_SECRET_KEY: testni nacin kot doslej (takoj `paid`, oznaka test_)
//   - TEST_PLACILA=true: vsili testni nacin SAMO ob sandbox kljucu ali brez kljuca. Ob LIVE kljucu (sk_live_) se IGNORIRA (zagon izpise
//     `[placila] POZOR ...`): ena napacna spremenljivka na Renderju sicer pomeni prave vstopnice brez placila (#191). Zagona NE zavrnemo: 503 v produkciji
//     je slabsi od tega, da prodaja gre skozi pravi Stripe.
//   - klub z dokoncanim Connect onboardingom (charges_enabled) ALI prodajalec je platforma (is_official, I50): Stripe
//   - SANDBOX kljuc (sk_test_), klub brez Stripa: se vedno testni nacin, da demo klubi in TestFlight delajo naprej
//   - LIVE kljuc (sk_live_), klub brez Stripa (ali z racunom iz sandboxa, I36): PLACLJIV nakup zavrnjen (409); znesek 0 EUR je kupljiv (I49, index.js `klubBrezStripaZavraNakup`)
//   - znesek 0 EUR: ne gre v Stripe (Checkout ima najmanjsi znesek), narocilo je takoj `paid` brez provizije (index.js, #191)
"use strict";
const Stripe = require("stripe");

// Pripeta razlicica API-ja: oblika dogodkov in parametrov se ne spremeni z nadgradnjo paketa.
const API_VERZIJA = "2025-03-31.basil";
const CHECKOUT_MINUT = 30;   // najkrajsi rok, ki ga Stripe dovoli za expires_at
const POSPRAVI_MS = 5 * 60 * 1000;

let predpomnjen = null;
function stripe() {
  const kljuc = process.env.STRIPE_SECRET_KEY;
  if (!kljuc) return null;
  if (predpomnjen && predpomnjen.kljuc === kljuc) return predpomnjen.s;
  const opcije = { apiVersion: API_VERZIJA, maxNetworkRetries: 2, timeout: 15000, appInfo: { name: "outly-backend" } };
  // Samo za teste: lazni Stripe streznik (STRIPE_API_BASE=http://localhost:PORT).
  if (process.env.STRIPE_API_BASE) {
    const u = new URL(process.env.STRIPE_API_BASE);
    opcije.host = u.hostname; opcije.port = Number(u.port); opcije.protocol = u.protocol.replace(":", "");
  }
  predpomnjen = { kljuc, s: new Stripe(kljuc, opcije) };
  return predpomnjen.s;
}
const jeSandbox = () => /^(sk|rk)_test_/.test(process.env.STRIPE_SECRET_KEY || "");
// LIVE = kljuc obstaja in NI sandbox (tudi nepoznana oblika kljuca velja za live: varnejsa smer).
const jeLive = () => !!process.env.STRIPE_SECRET_KEY && !jeSandbox();
// TEST_PLACILA=true ima ucinek samo, ce kljuca ni ali je sandbox (#191); ob live kljucu je ignoriran.
const testVsiljen = () => process.env.TEST_PLACILA === "true" && !jeLive();
// Sistem je v testnem nacinu za vse klube (nic se ne zaracuna): ni kljuca ali je testni nacin vsiljen (dashboard `mode`).
const testniNacin = () => testVsiljen() || !process.env.STRIPE_SECRET_KEY;
const webhookSkrivnosti = () => [process.env.STRIPE_WEBHOOK_SECRET, process.env.STRIPE_CONNECT_WEBHOOK_SECRET].filter(Boolean);
const osnovaSpleta = () => (process.env.APP_URL || "https://outly.si").replace(/\/+$/, "");

// "test" | "stripe" | "nastavitve" (kljuc brez webhook skrivnosti -> 503) | "klub" (live, klub brez Stripa -> 409)
function nacinPlacilaZ(klubImaStripe) {
  if (testVsiljen()) return "test";
  if (!process.env.STRIPE_SECRET_KEY) return "test";
  if (!process.env.STRIPE_WEBHOOK_SECRET) return "nastavitve";
  if (klubImaStripe) return "stripe";
  return jeSandbox() ? "test" : "klub";
}
// I36 (#227): Connect racun kluba je iz sandboxa ali iz zivega nacina (`clubs.stripe_account_livemode`, migracija 046): TRUE = zivi, FALSE = sandbox,
// NULL/manjka = neznano = SANDBOX (vsi zapisi pred 046 so iz sandboxa). Racun velja samo, ce se nacin ujema s kljucem (`jeLive()`); sicer je klub nepovezan
// (`stripe_charges_enabled` se ne upostevata). SQL enakovrednik: `sqlRacunVNacinu` v index.js.
const racunVNacinu = (klub) => !!klub && (klub.stripe_account_livemode === true) === jeLive();
// I50: prodajalec je platforma (uradni profil Outly, `clubs.is_official`): placilo neposredno na platformni racun, racun kluba ni pogoj. Natanko TRUE (fail closed).
// SQL enakovrednik za javni payment_mode: `sqlPlacilaPripravljena` v index.js.
const jePlatformniProdajalec = (klub) => !!klub && klub.is_official === true;
const nacinPlacila = (klub) => nacinPlacilaZ(jePlatformniProdajalec(klub) || !!(klub && klub.stripe_account_id && klub.stripe_charges_enabled && racunVNacinu(klub)));
// Oznaka na narocilu (orders.stripe_account_id), ki ga je prodajala platforma (I50): prodajalec je NEXT DIMENSIONS. Velja za VSA naroclila uradnega profila, tudi 0 EUR in testni
// nacin (pregled PR #302, 2. krog P2: sicer potrdilo in mail gostu 0 EUR vstopnice pisala »prodaja klub ... Outly je samo posrednik«). Navaden Stripe nakup tu hrani acct_...
// racun kluba, testni in brezplacni (0 EUR) nakup navadnega kluba NULL (nespremenjeno). Iz oznake odloca vse po nakupu (prikaz prodajalca, vracila, spori, finance), ne trenutna
// zastavica kluba (ta se lahko spremeni). Oznaka ne pomeni, da je placilo slo skozi Stripe: 0 EUR / PI `test_` gresta mimo Stripa po total_cents in PI (vracila_stripe.js izvedi).
const PLATFORMNI_RACUN = "platform";
const racunNarocila = (placanoTakoj, platformno, racunKluba) => (platformno ? PLATFORMNI_RACUN : (placanoTakoj ? null : racunKluba));
// SQL: narocilo, katerega prodajalec je platforma. `a` = alias tabele orders.
const SQL_NAROCILO_PLATFORMNO = (a = "orders") => `COALESCE(${a}.stripe_account_id = '${PLATFORMNI_RACUN}', FALSE)`;
// Vrednost za odjemalce (`payment_mode` v javnih odgovorih, #149): "test" (nic se ne zaracuna) | "stripe" (pravo placilo)
// | "unavailable" (nakup bi vrnil 409 »klub ne sprejema spletnih placil« ali 503 »placila niso nastavljena«). Natancnejsi javni `payment_mode`
// (po znesku: 0 EUR pri klubu brez Stripa je "stripe", I49; I34 seller_incomplete) racuna `javniNacinProdajalca` v index.js.
const javniNacin = (nacin) => (nacin === "test" || nacin === "stripe" ? nacin : "unavailable");

// Checkout seja za narocilo. Klicatelj narocilo ze ima (pending, v bazi). Vrne sejo ali vrze napako.
// Povratni naslovi: splet (/app) ali iOS. iOS (glava X-Outly-Client: ios) odpre Checkout v ASWebAuthenticationSession,
// ki se zapre, ko stran outly.si/placilo preusmeri na outly://placilo (callback shema). Seja v iOS nima spletne prijave,
// zato /app/... tam ne pride v postev.
function povratniNaslovi(odjemalec, ref, eventId) {
  if (odjemalec === "ios") {
    return {
      success_url: `${osnovaSpleta()}/placilo?stanje=uspeh&app=ios&narocilo=${ref}`,
      cancel_url: `${osnovaSpleta()}/placilo?stanje=preklic&app=ios&narocilo=${ref}`,
    };
  }
  return {
    success_url: `${osnovaSpleta()}/app/tickets?placilo=uspeh&narocilo=${ref}`,
    cancel_url: `${osnovaSpleta()}/app/event/${eventId}?placilo=preklic&narocilo=${ref}`,
  };
}

// Jezik Checkouta iz telesa nakupa (`locale`, neobvezno): "sl" ali "en" (tudi "sl-SI", "EN", "en_GB" -> primarna oznaka, male crke).
// Vse drugo (manjka, null, stevilo, "de", niz nad 20 znakov) -> undefined: polje se Stripu ne poslje (= Stripov `auto`). Nikoli napaka.
const CHECKOUT_JEZIKI = ["sl", "en"];
function normalizirajLocale(v) {
  if (typeof v !== "string" || v.length > 20) return undefined;
  const primarna = v.toLowerCase().split(/[-_]/)[0];
  return CHECKOUT_JEZIKI.includes(primarna) ? primarna : undefined;
}

// povratna: neobvezen { success_url, cancel_url } namesto privzetih (nakup brez racuna: success_url nosi zeton gosta, index.js).
// locale: ze normaliziran (normalizirajLocale) ali undefined; ponovitev z istim idempotentnim kljucem vrne obstojeco sejo (jezik prvega poskusa).
// platformno (I50): prodajalec je platforma -> seja brez transfer_data / on_behalf_of / application_fee_amount (neposredno placilo na platformni racun). Brez te zastavice je
// racun kluba OBVEZEN: manjkajoc racun navadnega kluba ne sme tiho postati neposredno placilo platformi (fail closed, Stripe se ne pokliche).
async function ustvariCheckout({ narocilo, opis, kolicina, cenaEnoteCents, racunKluba, platformno, email, eventId, odjemalec, povratna, locale }) {
  if (!platformno && !racunKluba) throw new Error("Checkout brez racuna kluba: prodajalec ni platforma");
  const s = stripe();
  const ref = encodeURIComponent(narocilo.public_ref);
  const meta = { order_id: String(narocilo.id), public_ref: narocilo.public_ref, ...(platformno ? { seller: "platform" } : {}) };
  return s.checkout.sessions.create({
    mode: "payment",
    client_reference_id: String(narocilo.id),
    customer_email: email || undefined,
    line_items: [{
      quantity: kolicina,
      price_data: { currency: String(narocilo.currency || "EUR").toLowerCase(), unit_amount: cenaEnoteCents, product_data: { name: opis.slice(0, 250) } },
    }],
    payment_intent_data: {
      ...(platformno ? {} : { application_fee_amount: narocilo.application_fee_cents, transfer_data: { destination: racunKluba }, on_behalf_of: racunKluba }),
      description: `${opis} (${narocilo.public_ref})`.slice(0, 1000),
      metadata: meta,
    },
    metadata: meta,
    expires_at: Math.floor(Date.now() / 1000) + CHECKOUT_MINUT * 60,
    ...(locale ? { locale } : {}),
    ...(povratna || povratniNaslovi(odjemalec, ref, eventId)),
  }, { idempotencyKey: `outly-narocilo-${narocilo.id}` });
}

// --- obdelava dogodkov (vse v transakciji klicatelja, odjemalec c) ---

function idNarocilaIzSeje(seja) {
  const v = seja.client_reference_id || (seja.metadata && seja.metadata.order_id);
  return /^\d+$/.test(String(v || "")) ? Number(v) : null;
}

// Placilo za narocilo, ki ga ne smemo vknjiziti (preklicano/neuspelo, brez imetnika ali znesek seje se ne ujema): kupec dobi VSE nazaj samodejno po isti poti
// kot odpoved dogodka (vracila_stripe.js), razlog `inactive_order` (nasa napaka: Stripovo pristojbino nosi Outly, provizija se vrne, #190), sicer samo alarm
// za rocno vracilo. Znesek = kar je kupec PLACAL (amount_total seje). Vrstica gre v vrsto v ISTI transakciji kot zapis webhooka (idempotentno: UNIQUE (order_id,
// razlog)); obdelovalec jo opravi v ozadju. `o.status` mora biti cancelled/failed. `opis` (neobvezno) = besedilo alarma.
async function vrniNeaktivno(c, o, seja, opis) {
  opis = opis || `placilo za neaktivno narocilo ${o.public_ref} (stanje ${o.status}, seja ${seja.id})`;
  const pi = typeof seja.payment_intent === "string" ? seja.payment_intent : (seja.payment_intent && seja.payment_intent.id) || null;
  const znesek = Number.isInteger(seja.amount_total) ? seja.amount_total : 0;
  if (pi && znesek > 0 && ["cancelled", "failed"].includes(o.status)) {
    const v = await c.query(
      `INSERT INTO vracila (order_id, event_id, razlog, znesek_cents, payment_intent_id, checkout_session_id, stripe_livemode, valuta)
       VALUES ($1, $2, 'inactive_order', $3, $4, $5, $6, $7) ON CONFLICT (order_id, razlog) DO NOTHING RETURNING id`,
      [o.id, o.event_id, znesek, pi, seja.id, typeof seja.livemode === "boolean" ? seja.livemode : null,
       typeof seja.currency === "string" && /^[a-z]{3}$/i.test(seja.currency) ? seja.currency.toUpperCase() : null]);   // #285 N3: znesek je v valuti SEJE (lahko drugacna od orders.currency), mail jo izpise

    console.error(`[stripe] POZOR: ${opis}: ${v.rows.length ? "vracilo v vrsti (samodejno)" : "vracilo je ze v vrsti"}.`);
  } else {
    console.error(`[stripe] POZOR: ${opis} - vrni rocno v Stripu.`);
  }
}

// Placilo uspelo: pending -> paid, nastanejo vstopnice. Idempotentno (drugic ne naredi nicesar).
// Vrne id narocila, ki je PRAVKAR postalo placano (sicer null): klicatelj po COMMIT-u sprozi stranske ucinke (mail gostu).
async function zakljuci(c, seja) {
  const id = idNarocilaIzSeje(seja);
  if (!id) { console.error(`[stripe] seja ${seja.id} brez narocila`); return null; }
  const r = await c.query(
    `SELECT id, public_ref, status, total_cents, currency, quantity, table_id, table_seats, event_id, stripe_checkout_session_id, user_id, guest_email, stripe_account_id
       FROM orders WHERE id = $1 FOR UPDATE`, [id]);
  if (!r.rows.length) { console.error(`[stripe] seja ${seja.id}: narocila ${id} ni`); return null; }
  const o = r.rows[0];
  if (o.stripe_checkout_session_id && o.stripe_checkout_session_id !== seja.id) {
    console.error(`[stripe] seja ${seja.id} se ne ujema z narocilom ${o.public_ref} (${o.stripe_checkout_session_id})`); return null;
  }
  if (o.status !== "pending") {
    if (!["paid", "partially_refunded", "refunded"].includes(o.status)) {
      // Placilo za ze preklicano/neuspelo narocilo (zaloga je bila sproscena). Ne vknjizimo ga (lahko bi presegli zalogo, vstopnic ni): kupec dobi VSE nazaj.
      await vrniNeaktivno(c, o, seja);
    }
    return null;
  }
  // #276 S4: naroceno brez imetnika (user_id IN guest_email NULL: racun izbrisan med odprtim Checkoutom) ne sme postati placano: vstopnice bi bile brez lastnika,
  // potrdila in maila ni. DELETE /me taka narocila ob izbrisu preklice, to je varovalo za tiste, ki so ze anonimizirana, in za tekmo z izbrisom.
  // Narocilo -> cancelled (sprozilec sprosti zalogo), PI zapisan (webhook charge.refunded ga najde), kupec dobi vse nazaj (`inactive_order`, I37).
  if (o.user_id === null && !o.guest_email) {
    const pi0 = typeof seja.payment_intent === "string" ? seja.payment_intent : (seja.payment_intent && seja.payment_intent.id) || null;
    await c.query(
      `UPDATE orders SET status = 'cancelled', cancelled_at = NOW(), stripe_payment_intent_id = COALESCE(stripe_payment_intent_id, $2),
              stripe_checkout_session_id = COALESCE(stripe_checkout_session_id, $3) WHERE id = $1`, [o.id, pi0, seja.id]);
    await vrniNeaktivno(c, { ...o, status: "cancelled" }, seja);
    return null;
  }
  if (seja.amount_total !== o.total_cents || String(seja.currency || "").toUpperCase() !== String(o.currency).toUpperCase()) {
    // #258 N3: kupec je placal, a znesek/valuta seje se ne ujema z narocilom (ne vknjizimo: vstopnice bi bile za drug znesek). Prej je narocilo ostalo `pending`
    // brez vstopnic in brez vracila, pospravljalec ga je vsakih 5 min znova obdelal. Zdaj: narocilo `cancelled` (sprozilec sprosti zalogo) in v ISTI transakciji
    // vracilo celotnega placanega zneska seje (`inactive_order`, ista pot kot placilo za preklicano narocilo). Ponovni webhook/pospravljalec vidi `cancelled`
    // in vracila ne podvoji (UNIQUE order_id, razlog).
    // Vrstni red (I44 #276 + N3): narocilo brez imetnika zgoraj ima prednost (isti izid: cancelled + vracilo). Kot tam se zapiseta PI in seja (COALESCE):
    // webhook charge.refunded/spor po PI najde preklicano narocilo (vracilo() ga pusti, ker ni placano) namesto da bi iskal po metadata.
    const piN = typeof seja.payment_intent === "string" ? seja.payment_intent : (seja.payment_intent && seja.payment_intent.id) || null;
    await c.query(
      `UPDATE orders SET status = 'cancelled', cancelled_at = NOW(), stripe_payment_intent_id = COALESCE(stripe_payment_intent_id, $2),
              stripe_checkout_session_id = COALESCE(stripe_checkout_session_id, $3) WHERE id = $1 AND status = 'pending'`, [o.id, piN, seja.id]);
    o.status = "cancelled";
    await vrniNeaktivno(c, o, seja,
      `znesek seje ${seja.id} (${seja.amount_total} ${seja.currency}) != narocilo ${o.public_ref} (${o.total_cents} ${o.currency}); narocilo preklicano`);
    return null;
  }
  const pi = typeof seja.payment_intent === "string" ? seja.payment_intent : (seja.payment_intent && seja.payment_intent.id) || null;
  // Isti zaklep kot spor(): spor, ki se sece z vknjizbo placila, ne sme zgresiti povezave (spor() bere narocilo po PI, zakljuci() poveze spor po PI; brez zaklepa bi vsak
  // videl samo necommitano stanje drugega).
  if (pi) await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", ["pi:" + pi]);
  await c.query(
    `UPDATE orders SET status = 'paid', paid_at = NOW(), stripe_payment_intent_id = $2,
            stripe_checkout_session_id = COALESCE(stripe_checkout_session_id, $3),
            -- Potrdilo kupcu z racunom (042, #95): naroceno ob prehodu v paid; gostujoce narocilo (user_id NULL) ima svoj mail (guest_mail_*).
            receipt_mail_attempts = COALESCE(receipt_mail_attempts, CASE WHEN user_id IS NOT NULL AND guest_list_id IS NULL THEN 0 END)
      WHERE id = $1`, [o.id, pi, seja.id]);
  const stevilo = o.table_id ? o.table_seats : o.quantity;
  await c.query(`INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [o.id, o.event_id, stevilo]);
  // #276 S2: spor je lahko prisel PREJ kot `checkout.session.completed` (narocila po PaymentIntentu se ni bilo): vrstica v `spori` je brez order_id, vstopnice
  // na vratih bi veljale. Zdaj ko je narocilo placano, spor povezemo z njim (sken ga bere po order_id; mail lastniku in povrnitev ob `lost` ujame obdelovalec).
  if (pi) {
    const sp = await c.query(
      `UPDATE spori SET order_id = $1, posodobljen_at = NOW(),
              -- Obvestilo lastniku: ob zapisu brez narocila je obdelovalec poskuse IZCRPAL (lastnika ni mogel poznati); zdaj ga poznamo, zato se neposlana obvestila ponovijo.
              mail_odprt_poskusi = CASE WHEN mail_odprt_poslano_at IS NULL THEN 0 ELSE mail_odprt_poskusi END,
              mail_odprt_prevzeto_at = CASE WHEN mail_odprt_poslano_at IS NULL THEN NULL ELSE mail_odprt_prevzeto_at END,
              mail_zaprt_poskusi = CASE WHEN mail_zaprt_poslano_at IS NULL THEN 0 ELSE mail_zaprt_poskusi END,
              mail_zaprt_prevzeto_at = CASE WHEN mail_zaprt_poslano_at IS NULL THEN NULL ELSE mail_zaprt_prevzeto_at END,
              -- I50: spor na naroclilo, ki ga je prodajala platforma, nima kluba, od katerega bi povrnitev terjali: ostane NULL (ni dolgovano), izgubo nosi Outly.
              povrnitev_stanje = CASE WHEN stanje = 'lost' AND povrnitev_stanje = 'rocno' AND povrnitev_napaka LIKE 'spor brez narocila%' THEN (CASE WHEN $3::boolean THEN NULL ELSE 'caka' END) ELSE povrnitev_stanje END,
              povrnitev_napaka = CASE WHEN stanje = 'lost' AND povrnitev_stanje = 'rocno' AND povrnitev_napaka LIKE 'spor brez narocila%' THEN NULL ELSE povrnitev_napaka END
        WHERE order_id IS NULL AND payment_intent_id = $2 RETURNING id`, [o.id, pi, o.stripe_account_id === PLATFORMNI_RACUN]);
    if (sp.rows.length) console.error(`[spori] POZOR: spor ${sp.rows.map((x) => x.id).join(", ")} je prisel pred placilom, povezan z narocilom ${o.public_ref}.`);
  }
  console.log(`[stripe] placano: narocilo ${o.public_ref}, ${stevilo} vstopnic`);
  return o.id;
}

// Odlozeno placilo (SEPA ipd.): seja je `complete`, denar pa se ni `paid` (pride async_payment_succeeded ali _failed, lahko po dnevih).
// Narocilo ostane `pending`, a povezava ni vec uporabna (kupec je ze opravil svoj del) in NI »potekla«: checkout_url postavimo na NULL
// (seja je ustvarjena, zato NULL + stripe_checkout_session_id pomeni »placilo v obdelavi«, `payment_processing` v odgovorih; ne rabi nove migracije).
async function oznaciVObdelavi(c, seja) {
  const id = idNarocilaIzSeje(seja);
  if (!id) return;
  const r = await c.query(
    `UPDATE orders SET checkout_url = NULL
      WHERE id = $1 AND status = 'pending' AND stripe_checkout_session_id = $2 AND checkout_url IS NOT NULL RETURNING public_ref`, [id, seja.id]);
  if (r.rows.length) console.log(`[stripe] narocilo ${r.rows[0].public_ref}: placilo v obdelavi (odlozeno placilo)`);
}

// Seja potekla ali placilo padlo: pending -> cancelled/failed (sprozilec sprosti zalogo, unikatni indeks mize jo spusti).
async function prekini(c, seja, stanje) {
  const id = idNarocilaIzSeje(seja);
  if (!id) return;
  const r = await c.query(
    `UPDATE orders SET status = $2, cancelled_at = NOW()
      WHERE id = $1 AND status = 'pending' AND (stripe_checkout_session_id IS NULL OR stripe_checkout_session_id = $3)
      RETURNING public_ref`, [id, stanje, seja.id]);
  if (r.rows.length) console.log(`[stripe] narocilo ${r.rows[0].public_ref} -> ${stanje}`);
}

// Stanje Connect racuna kluba.
// I36 (#227): posodobi samo klub, ki ima ta racun IN je racun iz tekocega nacina (stripe_account_livemode, NULL = sandbox): dogodek iz drugega nacina
// ne sme prepisati stanja (testni account.updated ob sk_live_ ne ugasne zivega racuna in obratno).
async function posodobiKlub(c, racun) {
  await c.query(
    `UPDATE clubs SET stripe_charges_enabled = $2, stripe_payouts_enabled = $3,
            stripe_onboarded_at = CASE WHEN $4 AND stripe_onboarded_at IS NULL THEN NOW() ELSE stripe_onboarded_at END
      WHERE stripe_account_id = $1 AND COALESCE(stripe_account_livemode, FALSE) = $5`,
    [racun.id, !!racun.charges_enabled, !!racun.payouts_enabled, !!racun.details_submitted, jeLive()]);
}

// Stanje narocila po vracilu: refunded_cents (nikoli navzdol), stanje, ob polnem vracilu vstopnice `refunded`. Ena funkcija za webhook `charge.refunded`
// (Stripova nadzorna plosca ali nase vracilo) IN obdelovalec vracil (vracila_stripe.js): isto stanje, idempotentno (drugic ne spremeni nicesar).
// o: { id, public_ref, total_cents, refunded_cents, status } (vrstica ze zaklenjena); vrnjenoCents: skupaj vrnjeno po Stripu (absolutno, ne prirastek).
async function uveljaviVracilo(c, o, vrnjenoCents, chargeId) {
  const vrnjeno = Math.min(o.total_cents, Math.max(o.refunded_cents || 0, Number(vrnjenoCents) || 0));
  const polno = vrnjeno >= o.total_cents;
  const stanje = polno ? "refunded" : (vrnjeno > 0 ? "partially_refunded" : o.status);
  await c.query("UPDATE orders SET refunded_cents = $2, status = $3, stripe_charge_id = COALESCE(stripe_charge_id, $4) WHERE id = $1",
    [o.id, vrnjeno, stanje, chargeId || null]);
  if (polno) await c.query("UPDATE tickets SET status = 'refunded' WHERE order_id = $1 AND status = 'valid'", [o.id]);
  return { vrnjeno, polno, stanje };
}

// Vracilo (iz Stripove nadzorne plosce ali API-ja): refunded_cents + stanje; ob polnem vracilu vstopnice `refunded`.
async function vracilo(c, charge) {
  const pi = typeof charge.payment_intent === "string" ? charge.payment_intent : (charge.payment_intent && charge.payment_intent.id);
  if (!pi) return;
  const r = await c.query("SELECT id, public_ref, total_cents, refunded_cents, status, guest_list_id FROM orders WHERE stripe_payment_intent_id = $1 FOR UPDATE", [pi]);
  if (!r.rows.length) {
    // #276 S2: PaymentIntent se zapise na narocilo sele v zakljuci() (checkout.session.completed). Ce je vracilo prislo PREJ (completed je padel/zamujen), bi ga tiho
    // izgubili (dogodek bi bil zabelezen kot obdelan), narocilo pa bi pozneje postalo `paid` z veljavnimi vstopnicami, denar pa je vrnjen. Zato: naboj nosi
    // metadata.order_id (PaymentIntent metadata se prekopira); ce to narocilo obstaja in se caka na placilo (`pending`), VRZI napako (transakcija se vrne, dogodek se NE zabelezi,
    // Stripe ponavlja do 3 dni) - ob ponovitvi je narocilo ze `paid`. Vse ostalo (tuj PI, brez metadata, narocilo je ze preklicano/neuspelo) se ne bo nikoli ujemalo:
    // zanemari, da ne nastanejo neskoncne ponovitve.
    const oid = charge.metadata && /^\d+$/.test(String(charge.metadata.order_id || "")) ? Number(charge.metadata.order_id) : null;
    // FOR UPDATE brez pogoja na status: ce zakljuci() ta hip vknjizuje placilo, pocakamo na njegov COMMIT in vidimo `paid` + PI (sicer bi branje brez zaklepa
    // videlo staro stanje ali pa ze `paid` in dogodek bi se izgubil). Ponovitev: pending ALI naroceno ze nosi ta PI (pravilna veja ga obdela ob ponovitvi).
    const nar = oid ? (await c.query("SELECT status, stripe_payment_intent_id AS pi FROM orders WHERE id = $1 FOR UPDATE", [oid])).rows[0] : null;
    const cakajoce = !!nar && (nar.status === "pending" || nar.pi === pi);
    if (cakajoce) {
      const e = new Error(`vracilo ${charge.id} je prislo pred placilom narocila ${oid}`);
      e.ponovi = true;
      e.charge = charge.id;
      throw e;
    }
    console.log(`[stripe] vracilo ${charge.id}: narocila za PaymentIntent ni${oid ? ` (metadata narocilo ${oid} ni v cakanju)` : " (brez metadata.order_id)"} - zanemarjeno`);
    return;
  }
  const o = r.rows[0];
  if (!["paid", "partially_refunded", "refunded"].includes(o.status)) return;
  const u = await uveljaviVracilo(c, o, Number(charge.amount_refunded) || 0, charge.id);
  console.log(`[stripe] vracilo: narocilo ${o.public_ref}, ${u.vrnjeno} c${u.polno ? " (polno)" : ""}`);
  // #309: obvestilo kupcu natanko enkrat na NABOJ (vracila_iz_stripa, 053), v ISTI transakciji kot stanje narocila. Mail gre po COMMIT-u (naVraciluIzStripa) in ga
  // ponavlja pospravljalec; NE gre, dokler ima naroceno vrstico v `vracila` (nase vracilo: kupca obvesca obdelovalec). Znesek = skupaj vrnjeno na naboju po Stripu
  // (delno vracilo = delni znesek), dokler mail ni poslan, ga novejsi dogodek lahko poveca. Brez maila: guest lista, 0 EUR, testni nacin (test_ PI).
  const zn = Math.min(o.total_cents, Math.max(0, Number(charge.amount_refunded) || 0));
  if (zn > 0 && o.total_cents > 0 && o.guest_list_id === null && !/^test_/.test(pi)) {
    await c.query(
      `INSERT INTO vracila_iz_stripa (charge_id, order_id, znesek_cents, valuta) VALUES ($1, $2, $3, $4)
       ON CONFLICT (charge_id) DO UPDATE SET znesek_cents = GREATEST(vracila_iz_stripa.znesek_cents, EXCLUDED.znesek_cents), posodobljeno_at = NOW()
        WHERE vracila_iz_stripa.mail_poslano_at IS NULL`,
      [String(charge.id), o.id, zn, charge.currency ? String(charge.currency).toUpperCase().slice(0, 3) : null]);
  }
}

// Spor (chargeback, #190): zapis stanja v `spori` in alarm. Takoj ob odprtju spora vstopnice naroceno na vratih ne veljajo vec (sken: payment_disputed, brez klica Stripa: indeksiran
// EXISTS po `spori`); ob `won`/`warning_closed`/`prevented` spet veljajo, ob `lost` ostanejo neveljavne. Ob `lost` se v isti transakciji vrstici nastavi povrnitev_stanje='caka':
// transfer reversal od kluba izvede obdelovalec (vracila_stripe.js, Martin 12. 10. 2026: izgubljen spor nosi klub).
// I50: spor na naroclilo, ki ga je prodajala platforma (SQL_NAROCILO_PLATFORMNO), ne sprozi povrnitve od kluba (povrnitev_stanje ostane NULL) in ne obvesti nobenega lastnika.
// Objekt je svez iz Stripa (svezObjekt), zato zaporedje dogodkov (created/updated/closed) ni pomembno: vedno zapisemo trenutno stanje.
// Narocilo najdemo po PaymentIntentu ali naboju (charge); spor brez narocila se zapise (order_id NULL) in sproži alarm.
// Stripovi statusi (docs.stripe.com/api/disputes/object): warning_needs_response, warning_under_review, warning_closed, needs_response, under_review, won, lost, prevented.
// Zaprt = won | lost | warning_closed | prevented. Vstopnice naroceno so NA VRATIH neveljavne, dokler spor ni zaprt, in za vedno ob `lost` (index.js: SQL_SPOR_ODPRT).
const SPOR_NAROCILO_PLACANO = ["paid", "partially_refunded", "refunded"];
const SPOR_ZAPRT = ["won", "lost", "warning_closed", "prevented"];
async function spor(c, dp) {
  const idOd = (v) => (typeof v === "string" ? v : (v && v.id) || null);
  const pi = idOd(dp.payment_intent), ch = idOd(dp.charge);
  if (pi) await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", ["pi:" + pi]);   // serializacija z zakljuci() (glej tam): spor se poveze natanko enkrat
  let n = null;
  const PL = `${SQL_NAROCILO_PLATFORMNO("orders")} AS platformno`;
  if (pi) n = (await c.query(`SELECT id, public_ref, status, ${PL} FROM orders WHERE stripe_payment_intent_id = $1`, [pi])).rows[0] || null;
  if (!n && ch) n = (await c.query(`SELECT id, public_ref, status, ${PL} FROM orders WHERE stripe_charge_id = $1`, [ch])).rows[0] || null;
  // I50: prodajalec je platforma (uradni profil Outly): spor ne bremeni nobenega kluba. Zapis in alarm kot vedno, povrnitve od kluba (transfer reversal) NI in lastnik ne dobi maila.
  const platformno = !!(n && n.platformno);
  const zaprt = SPOR_ZAPRT.includes(dp.status);
  // #285: spor na naroceno, ki NI placano (cancelled/failed/pending: I44, N3 #258, placilo po preklicu) nima vstopnic in ni pogodbena terjatev do kluba: `inactive_order` je nasa napaka
  // (pristojbino nosi Outly), zato povrnitev od kluba NI samodejna (`rocno`, odloci Martin) in lastnik kluba ne dobi maila (index.js: SQL_SPOR_NAROCILO_PLACANO).
  const placano = !n || SPOR_NAROCILO_PLACANO.includes(n.status);
  const rok = dp.evidence_details && Number.isInteger(dp.evidence_details.due_by) ? new Date(dp.evidence_details.due_by * 1000) : null;
  const ustvarjen = Number.isInteger(dp.created) ? new Date(dp.created * 1000) : new Date();
  const znesek = Number.isInteger(dp.amount) && dp.amount >= 0 ? dp.amount : 0;
  const prej = (await c.query("SELECT stanje FROM spori WHERE id = $1", [dp.id])).rows[0];
  await c.query(
    `INSERT INTO spori (id, order_id, payment_intent_id, charge_id, stanje, razlog, znesek_cents, valuta, rok_dokazov_at, ustvarjen_at, zaprt_at, povrnitev_stanje, povrnitev_napaka)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CASE WHEN $11 THEN NOW() END, CASE WHEN $5 = 'lost' AND NOT $13::boolean THEN (CASE WHEN $2::bigint IS NULL OR NOT $12::boolean THEN 'rocno' ELSE 'caka' END) END,
            CASE WHEN $13::boolean THEN NULL
                 WHEN $5 = 'lost' AND $2::bigint IS NULL THEN 'spor brez narocila: povrnitve od kluba ni mogoce izracunati'
                 WHEN $5 = 'lost' AND NOT $12::boolean THEN 'spor na neplacanem/preklicanem narocilu: povrnitev od kluba ni samodejna, odloci rocno' END)
     ON CONFLICT (id) DO UPDATE SET stanje = EXCLUDED.stanje, razlog = EXCLUDED.razlog, order_id = COALESCE(spori.order_id, EXCLUDED.order_id),
            rok_dokazov_at = EXCLUDED.rok_dokazov_at, zaprt_at = COALESCE(spori.zaprt_at, EXCLUDED.zaprt_at), posodobljen_at = NOW(),
            povrnitev_stanje = COALESCE(spori.povrnitev_stanje, EXCLUDED.povrnitev_stanje),
            povrnitev_napaka = CASE WHEN spori.povrnitev_stanje IS NULL AND EXCLUDED.povrnitev_stanje = 'rocno' THEN EXCLUDED.povrnitev_napaka
                 WHEN spori.povrnitev_stanje = 'rocno' AND spori.order_id IS NULL AND EXCLUDED.order_id IS NOT NULL AND NOT $12::boolean THEN 'spor na neplacanem/preklicanem narocilu: povrnitev od kluba ni samodejna, odloci rocno'
                 ELSE spori.povrnitev_napaka END`,
    [dp.id, n ? n.id : null, pi, ch, String(dp.status || "unknown").slice(0, 40), dp.reason ? String(dp.reason).slice(0, 60) : null, znesek,
     dp.currency ? String(dp.currency).toUpperCase().slice(0, 3) : null, rok, ustvarjen, zaprt, placano, platformno]);
  const kaj = `spor ${dp.id} (${dp.reason || "?"}) ${znesek} c, stanje ${dp.status}, narocilo ${n ? n.public_ref : "NEZNANO"}`;
  // #285 N4: izgubljen spor, kupec pa je ze dobil mail »vracilo se ni izvedeno, uredili ga bomo rocno«: obljuba je zdaj napacna (denar je dobil prek banke).
  if (dp.status === "lost" && (!prej || prej.stanje !== "lost") && (n || pi)) {
    const ob = await c.query(
      `SELECT v.id FROM vracila v WHERE v.mail_ni_izvedeno_poslano_at IS NOT NULL AND (($1::bigint IS NOT NULL AND v.order_id = $1) OR ($2::text IS NOT NULL AND v.payment_intent_id = $2)) LIMIT 1`,
      [n ? n.id : null, pi]);
    if (ob.rows.length) console.error(`[vracila] POZOR: ${kaj}: kupec je ze dobil mail »vracilo se ni izvedeno, uredili ga bomo rocno« (vracilo ${ob.rows[0].id}), zdaj je denar dobil prek izgubljenega spora - NE vracaj rocno.`);
  }
  if (!n) console.error(`[spori] POZOR: ${kaj} - spora ni mogoce povezati z narocilom, preveri v Stripu.${dp.status === "lost" ? " IZGUBLJEN: povrnitev od kluba NI sprozena (rocno)." : ""}`);
  else if (!placano && (!prej || zaprt)) console.error(`[spori] POZOR: spor na neplacanem/preklicanem narocilu ${n.public_ref} (${n.status}): ${kaj} - povrnitev od kluba NI samodejna, lastnik kluba NI obvescen, odloci rocno.`);
  else if (!placano) console.log(`[spori] posodobljen ${kaj} (narocilo ni placano)`);
  else if (!prej) console.error(`[spori] POZOR: nov ${kaj}. Vstopnice naroceno na vratih NE veljajo do konca spora; ${platformno ? "prodajalec je platforma (uradni profil Outly): lastnik kluba NI obvescen, dokaze odda Outly v Stripu" : "lastnik kluba je obvescen"}. Rok za dokaze: ${rok ? rok.toISOString() : "?"}.`);
  else if (zaprt) console.error(`[spori] POZOR: spor zaprt: ${kaj}.${dp.status === "lost" ? (platformno ? " Izgubljen: prodajalec je platforma (uradni profil Outly), izgubo nosi Outly, od nobenega kluba se ne terja; vstopnice ostanejo neveljavne." : " Izgubljen: povrnitev od kluba (transfer reversal) je v vrsti, vstopnice ostanejo neveljavne.") : " Vstopnice spet veljajo."}`);
  else console.log(`[spori] posodobljen ${kaj}`);
}

// Objekt dogodka preberemo SVEZ iz Stripa (pripeta API razlicica): oblika webhooka je odvisna od razlicice endpointa v
// nadzorni plosci, ne od nas, in svez objekt je tudi dodatna potrditev, da dogodek ni ponarejen.
async function svezObjekt(s, d) {
  const o = d.data && d.data.object;
  if (!o || !o.id) return o;
  if (d.type.startsWith("checkout.session.")) return s.checkout.sessions.retrieve(o.id);
  if (d.type === "charge.refunded") return s.charges.retrieve(o.id);
  if (d.type === "account.updated") return s.accounts.retrieve(o.id);
  if (d.type.startsWith("charge.dispute.")) return s.disputes.retrieve(o.id);
  if (d.type === "refund.updated" || d.type === "refund.failed" || d.type === "charge.refund.updated") return s.refunds.retrieve(o.id);
  return o;
}

// Vrne id narocila, ki je s tem dogodkom postalo placano (ali null).
async function obdelajDogodek(c, d, o) {
  switch (d.type) {
    case "checkout.session.completed":
      if (o.payment_status === "paid") return zakljuci(c, o);   // "unpaid" = odlozeno placilo, pride async_payment_succeeded
      if (o.status === "complete") await oznaciVObdelavi(c, o);
      break;
    case "checkout.session.async_payment_succeeded": return zakljuci(c, o);
    case "checkout.session.expired": await prekini(c, o, "cancelled"); break;
    case "checkout.session.async_payment_failed": await prekini(c, o, "failed"); break;
    case "account.updated": await posodobiKlub(c, o); break;
    case "charge.refunded": await vracilo(c, o); break;
    case "charge.dispute.created": case "charge.dispute.updated": case "charge.dispute.closed": await spor(c, o); break;
    case "refund.updated": case "refund.failed": case "charge.refund.updated": break;   // izid Stripovega vracila: po COMMIT-u (naVracilu)
    default: break;   // drugi dogodki: samo zabelezeni
  }
  return null;
}

// naPlacano(idNarocila): neobvezen povratni klic PO COMMIT-u, ko narocilo postane placano (webhook ali pospravljalec). Njegova napaka
// ne sme podreti webhooka (Stripe bi ponavljal) ne pospravljalca; klicatelj jo ujame sam, tu je se varovalka.
function ustvari({ pool, naPlacano, naSporu, naVracilu, naVraciluIzStripa }) {
  const poPlacilu = (id) => {
    if (!id || !naPlacano) return;
    try { Promise.resolve(naPlacano(id)).catch((e) => console.error("[stripe] naPlacano:", e && e.message)); }
    catch (e) { console.error("[stripe] naPlacano:", e && e.message); }
  };
  // POST /stripe/webhook (surovo telo!). 400 = napacen podpis, 500 = obdelava ni uspela (Stripe ponovi), 200 = obdelano ali ze videno.
  async function webhook(req, res) {
    const s = stripe();
    const skrivnosti = webhookSkrivnosti();
    if (!s || !skrivnosti.length) return res.status(503).send("Stripe is not configured.");
    const podpis = req.headers["stripe-signature"];
    if (!podpis || !Buffer.isBuffer(req.body)) return res.status(400).send("Missing signature.");
    let d = null;
    for (const sk of skrivnosti) {
      try { d = s.webhooks.constructEvent(req.body, podpis, sk); break; } catch (_) { /* naslednja skrivnost */ }
    }
    if (!d) return res.status(400).send("Invalid signature.");
    // I36 (#227): dogodek iz DRUGEGA nacina ne sme spremeniti stanja ali sprozati klicev. `livemode` ima vsak pravi Stripov dogodek (manjka samo v lazni strezniku).
    //  - sandbox dogodek ob sk_live_ (npr. webhook sandbox endpointa z napacno skrivnostjo): svezObjekt bi ga z zivim kljucem poiskal in dobil 404 -> 502 -> Stripe
    //    ponavlja dneve. Sandbox narocil z zivim kljucem tako ali tako ni mogoce zakljuciti, zato 200 in zanemari (pending sandbox narocila pospravi pospravljalec).
    //  - zivi dogodek ob sandbox kljucu: samo `account.updated` (stanje, ki ga posodobiKlub varuje tudi po nacinu racuna); placilnih dogodkov NE zavrzemo
    //    (napacen kljuc ob zivem webhooku ne sme tiho izgubiti placila: ostane 502/napaka v dnevniku, kot doslej).
    if (typeof d.livemode === "boolean" && d.livemode !== jeLive() && (d.livemode === false || d.type === "account.updated")) {
      console.log(`[stripe] webhook ${d.type} ${d.id}: dogodek iz ${d.livemode ? "zivega" : "sandbox"} nacina, kljuc je ${jeLive() ? "ziv" : "sandbox"} - zanemarjen`);
      return res.json({ received: true, ignored: "livemode" });
    }
    let objekt;
    try { objekt = await svezObjekt(s, d); }
    catch (e) { console.error(`[stripe] webhook ${d.type} ${d.id}: branje objekta ni uspelo:`, e.message); return res.status(502).send("Try again."); }
    let c;
    try { c = await pool.connect(); } catch (e) { console.error("[stripe] webhook brez baze:", e.message); return res.status(503).send("Try again."); }
    try {
      await c.query("BEGIN");
      const nov = await c.query("INSERT INTO stripe_events (id, type) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id", [d.id, d.type]);
      if (!nov.rows.length) { await c.query("ROLLBACK"); return res.json({ received: true, duplicate: true }); }
      const placano = await obdelajDogodek(c, d, objekt);
      await c.query("COMMIT");
      poPlacilu(placano);
      // Spor: obvestilo lastniku kluba PO COMMIT-u (napaka maila ne podre webhooka; neposlano ponovi obdelovalec).
      if (naSporu && d.type.startsWith("charge.dispute.") && objekt && objekt.id) {
        try { Promise.resolve(naSporu(objekt.id)).catch((e) => console.error("[spori] obvestilo:", e && e.message)); }
        catch (e) { console.error("[spori] obvestilo:", e && e.message); }
      }
      // #309: mail kupcu o vracilu iz Stripove nadzorne plosce (vracila_iz_stripa) po COMMIT-u, brez cakanja; napaka ne podre webhooka (ponovi pospravljalec).
      if (naVraciluIzStripa && d.type === "charge.refunded" && objekt && objekt.id) {
        try { Promise.resolve(naVraciluIzStripa(String(objekt.id))).catch((e) => console.error("[vracila] mail vracila iz Stripa:", e && e.message)); }
        catch (e) { console.error("[vracila] mail vracila iz Stripa:", e && e.message); }
      }
      // Izid Stripovega vracila (pending -> succeeded | failed | canceled; vracila_stripe.js): po COMMIT-u, napaka ne podre webhooka.
      if (naVracilu && ["refund.updated", "refund.failed", "charge.refund.updated"].includes(d.type) && objekt && objekt.id) {
        try { Promise.resolve(naVracilu(objekt)).catch((e) => console.error("[vracila] webhook refund:", e && e.message)); }
        catch (e) { console.error("[vracila] webhook refund:", e && e.message); }
      }
      return res.json({ received: true });
    } catch (e) {
      await c.query("ROLLBACK").catch(() => {});
      if (e && e.ponovi) {
        // Redko: nekaj sekund/minut je normalno (completed zamuja). Starejse od 1 h = naroceno obtici v `pending`, Stripe preneha ponavljati po 3 dneh -> alarm (Sentry).
        const starost = Number.isInteger(d.created) ? Date.now() / 1000 - d.created : 0;
        if (starost > 3600) console.error(`[stripe] POZOR: ${d.type} ${d.id} caka na placilo ze ${Math.round(starost / 60)} min (${e.message}); Stripe preneha ponavljati po 3 dneh, vracilo se lahko izgubi - preveri narocilo`);
        else console.log(`[stripe] webhook ${d.type} ${d.id}: ${e.message} - Stripe ponovi`);
        return res.status(503).send("Try again.");
      }
      console.error(`[stripe] webhook ${d.type} ${d.id} ni uspel:`, e);
      return res.status(500).send("Webhook processing failed.");
    } finally { c.release(); }
  }

  async function vTransakciji(fn) {
    const c = await pool.connect();
    try { await c.query("BEGIN"); await fn(c); await c.query("COMMIT"); }
    catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
    finally { c.release(); }
  }

  // Eno cakajoce narocilo s sejo: vprasaj Stripe, kaj je res (pospravljalec in potekel checkout_url, #149). Brez seje -> failed.
  // Idempotentno: zakljuci/prekini zaklenita vrstico in ponovni klic ne naredi nicesar. Napaka (Stripe nedosegljiv) se vrze klicatelju.
  // smemIsteci: samo pospravljalec (5 min po roku) sme `expire()` na seji, ki je po Stripu se `open`; preverjanje ob branju (preveriPoteklo) ne:
  // kupec je lahko sredi 3DS in expire() bi preklical njegovo placilo.
  async function preveriEno(o, smemIsteci = true) {
    const s = stripe();
    if (!o.stripe_checkout_session_id) {
      await pool.query("UPDATE orders SET status = 'failed', cancelled_at = NOW() WHERE id = $1 AND status = 'pending'", [o.id]);
      console.log(`[stripe] pospravljeno: narocilo ${o.public_ref} brez seje -> failed`);
      return;
    }
    // I36 (#227): sandbox seja (cs_test_) ob zivem kljucu: Stripe jo z zivim kljucem ne pozna (resource_missing), pospravljalec bi jo spraseval vsakih 5 min v
    // nedogled in z napakami zasedal okno 50 narocil. Narocilo je potekla neplacana sandbox seja (rok + 5 min je mimo; v zivem je ni mogoce placati ali zakljuciti),
    // zato ga zapremo kot `cancelled` brez klica Stripa (sprozilec sprosti zalogo). Nikoli v obratni smeri (cs_live_ ob sandbox kljucu): tam bi lahko bilo placilo
    // v obdelavi in prekinitev bi izgubila denar.
    if (jeLive() && /^cs_test_/.test(o.stripe_checkout_session_id)) {
      const r = await pool.query("UPDATE orders SET status = 'cancelled', cancelled_at = NOW() WHERE id = $1 AND status = 'pending' AND stripe_payment_intent_id IS NULL RETURNING public_ref", [o.id]);
      if (r.rows.length) console.log(`[stripe] pospravljeno: narocilo ${r.rows[0].public_ref} ima sandbox sejo (${o.stripe_checkout_session_id}), kljuc je ziv -> cancelled`);
      return;
    }
    let seja = await s.checkout.sessions.retrieve(o.stripe_checkout_session_id);
    if (seja.status === "open") {
      if (!smemIsteci) return;
      seja = await s.checkout.sessions.expire(seja.id);
    }
    if (seja.status === "complete" && seja.payment_status === "paid") {
      let placano = null;
      await vTransakciji(async (c) => { placano = await zakljuci(c, seja); });
      poPlacilu(placano);
    }
    else if (seja.status === "expired") await vTransakciji((c) => prekini(c, seja, "cancelled"));
    else if (seja.status === "complete") {
      // Odlozeno placilo (seja opravljena, ni paid): navadno pocakamo na async webhook. Ce je ta izgubljen (Stripe jih po 3 dneh preneha ponavljati),
      // bi narocilo drzalo zalogo neomejeno, zato preberemo PaymentIntent: `canceled` ali `requires_payment_method` = placilo je padlo -> failed (zaloga prosta).
      // `processing` / `requires_action` ... = denar je se na poti, ostane v obdelavi.
      const pi = typeof seja.payment_intent === "string" ? seja.payment_intent : (seja.payment_intent && seja.payment_intent.id) || null;
      let padlo = false;
      if (pi) {
        const st = typeof seja.payment_intent === "object" && seja.payment_intent.status ? seja.payment_intent.status : (await s.paymentIntents.retrieve(pi)).status;
        padlo = st === "canceled" || st === "requires_payment_method";
      }
      if (padlo) await vTransakciji((c) => prekini(c, seja, "failed"));
      else await vTransakciji((c) => oznaciVObdelavi(c, seja));
    }
  }

  // Narocila, ki cakajo predolgo (izgubljen webhook, padla seja): vprasaj Stripe, kaj je res.
  let tece = false;
  async function pospravi() {
    const s = stripe();
    if (!s || tece) return;
    tece = true;
    try {
      const r = await pool.query(
        `SELECT id, public_ref, stripe_checkout_session_id FROM orders
          WHERE status = 'pending' AND stripe_payment_intent_id IS NULL
            AND ((checkout_expires_at IS NOT NULL AND checkout_expires_at < NOW() - INTERVAL '5 minutes')
              OR (checkout_expires_at IS NULL AND created_at < NOW() - INTERVAL '15 minutes'))
          ORDER BY (checkout_url IS NULL AND stripe_checkout_session_id IS NOT NULL), created_at LIMIT 50`);   // odlozena placila (v obdelavi) zadnja: ne stradajo drugih
      for (const o of r.rows) {
        try { await preveriEno(o); }
        catch (e) { console.error(`[stripe] pospravljanje narocila ${o.public_ref}:`, e.message); }
      }
    } catch (e) { console.error("[stripe] pospravljanje:", e.message); }
    finally { tece = false; }
  }

  // Potekel checkout_url (#149): seja ima rok (expires_at), cakajoce narocilo pa ostane `pending`, dokler ga ne pospravi pospravljalec
  // (do ~10 min po roku). V tem oknu odgovori NE smejo vec vracati checkout_url (kupec bi odprl potekel obrazec). Namesto da cakamo na
  // pospravljalca, narocilo preverimo takoj: Stripe pove, ali je bilo placano tik pred rokom (-> paid), ali je seja potekla (-> cancelled).
  // Zascita Stripove omejitve branja: najvec en klic hkrati in najvec eden na PREVERI_OKNO_MS po narocilu (kot preklic gosta, GOST_PREKLIC_OKNO_MS);
  // klicatelj po klicu ponovno prebere narocilo in presodi na SVEZEM stanju (ob zavrnjenem klicu je se vedno `pending`).
  // Vrne true, ce je narocilo zdaj preverjeno (ali ga ni vec treba), false ob omejitvi, napaki Stripa ali ob preteku roka cakanja.
  // Cakanje klicatelja je omejeno na PREVERI_ROK_MS (4 s): Stripov odjemalec ob zastoju caka do 3 x 15 s, GET /me/orders (zagon aplikacije) pa ne sme
  // viseti tako dolgo. Preverjanje se v ozadju konca samo (ostane v mnozici v teku, zato ga ponovni klici ne podvojijo).
  const preveriVObdelavi = new Set();
  const preveriZadnji = new Map();   // order_id -> ms zadnjega klica; najvec 5000 vnosov
  const razcleni = (ime, privzeto, najvec) => { const n = Number.parseInt(process.env[ime], 10); return Number.isInteger(n) && n >= 0 && n <= najvec ? n : privzeto; };
  const PREVERI_OKNO_MS = razcleni("PREVERI_OKNO_MS", 5000, 600000);   // samo za teste (0 = brez razmika)
  const PREVERI_ROK_MS = razcleni("PREVERI_ROK_MS", 4000, 60000);
  // Odlog po roku seje: kupec je lahko sredi 3DS ali potrjevanja v banki; Stripe seje ob roku ne zapre takoj. Do takrat odgovor kaze
  // checkout_expired, a Stripa ne sprasujemo (pospravljalec ima svojih 5 min).
  const PREVERI_ODLOG_MS = razcleni("PREVERI_ODLOG_MS", 120000, 3600000);
  async function preveriPotekloDelo(oid) {
    const kljuc = String(oid);
    if (preveriVObdelavi.has(kljuc)) return false;
    const zdaj = Date.now(), zadnji = preveriZadnji.get(kljuc);
    if (zadnji !== undefined && zdaj - zadnji < PREVERI_OKNO_MS) return false;
    preveriVObdelavi.add(kljuc);
    try {
      const r = await pool.query(
        `SELECT id, public_ref, stripe_checkout_session_id FROM orders
          WHERE id = $1 AND status = 'pending' AND stripe_payment_intent_id IS NULL
            AND checkout_expires_at IS NOT NULL AND checkout_expires_at <= NOW() - ($2::bigint * INTERVAL '1 millisecond')
            AND checkout_url IS NOT NULL`, [oid, PREVERI_ODLOG_MS]);   // v obdelavi (url NULL) ni potekla
      if (!r.rows.length) return true;   // ni (vec) cakajoce s poteklo sejo
      try { await preveriEno(r.rows[0], false); return true; }
      catch (e) { console.error(`[stripe] preverjanje potekle seje narocila ${r.rows[0].public_ref}:`, e && e.message); return false; }
    } finally {
      preveriVObdelavi.delete(kljuc);
      preveriZadnji.delete(kljuc);
      if (preveriZadnji.size >= 5000) {
        const meja = Date.now() - PREVERI_OKNO_MS;
        for (const [k, t] of preveriZadnji) if (t <= meja) preveriZadnji.delete(k);
        while (preveriZadnji.size >= 5000) preveriZadnji.delete(preveriZadnji.keys().next().value);
      }
      preveriZadnji.set(kljuc, Date.now());
    }
  }
  async function preveriPoteklo(oid) {
    if (!stripe()) return false;
    let t;
    const delo = preveriPotekloDelo(oid).catch((e) => { console.error("[stripe] preverjanje potekle seje:", e && e.message); return false; });
    try { return await Promise.race([delo, new Promise((r) => { t = setTimeout(() => r(false), PREVERI_ROK_MS); })]); }
    finally { clearTimeout(t); }
  }

  function zazeni() {
    // Produkcija (Render nastavi RENDER) brez Stripe ključa ali s sandbox ključem ali z vsiljenim testnim nacinom: vstopnice se izdajajo BREZ placila
    // (klubi brez Connecta). Danes je to namerno (TestFlight, demo klubi), zato samo glasno opozorilo, brez blokade (I31).
    if ((process.env.RENDER || process.env.NODE_ENV === "production") && (!process.env.STRIPE_SECRET_KEY || jeSandbox() || testVsiljen())) {
      console.error("[placila] POZOR: placila v TESTNEM nacinu — vstopnice brez placila (" + (!process.env.STRIPE_SECRET_KEY ? "brez STRIPE_SECRET_KEY" : jeSandbox() ? "sandbox kljuc sk_test_" : "TEST_PLACILA=true") + "). Pred prodajo nastavi zivi kljuc.");
    }
    if (!process.env.STRIPE_SECRET_KEY) return;
    if (process.env.TEST_PLACILA === "true" && jeLive()) {
      console.error("[placila] POZOR: TEST_PLACILA=true je nastavljen ob ZIVEM Stripe kljucu (sk_live_). IGNORIRAN: nakupi gredo prek pravega Stripa, testni nacin se ne vklopi. Odstrani TEST_PLACILA iz okolja (Render).");
    }
    if (!process.env.STRIPE_WEBHOOK_SECRET) console.error("OPOZORILO: STRIPE_SECRET_KEY je nastavljen, STRIPE_WEBHOOK_SECRET pa ne - Stripe nakupi vracajo 503.");
    console.log(`[stripe] vklopljen (${jeSandbox() ? "SANDBOX" : "LIVE"}), API ${API_VERZIJA}`);
    setInterval(() => { pospravi(); }, Number(process.env.STRIPE_POSPRAVI_MS) || POSPRAVI_MS).unref();
  }

  return { webhook, pospravi, zazeni, preveriPoteklo };
}

module.exports = { uveljaviVracilo, povratniNaslovi, ustvari, stripe, jeSandbox, jeLive, testniNacin, racunVNacinu, nacinPlacila, nacinPlacilaZ, jePlatformniProdajalec, PLATFORMNI_RACUN, racunNarocila, SQL_NAROCILO_PLATFORMNO, javniNacin, ustvariCheckout, normalizirajLocale, osnovaSpleta, CHECKOUT_MINUT, API_VERZIJA };
