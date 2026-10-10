// Stripe Checkout + Connect Express (issue #19).
//
// Model (DECISIONS 2026-09): prodajalec je KLUB, Outly je posrednik s provizijo. Tehnicno: destination charge
// (transfer_data.destination = racun kluba) z application_fee_amount (provizija) in on_behalf_of = racun kluba,
// da je klub tudi »business of record« (pravna analiza 1. 10. 2026, V1: brez on_behalf_of bi bil to Outly).
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
//   - klub z dokoncanim Connect onboardingom (charges_enabled): Stripe
//   - SANDBOX kljuc (sk_test_), klub brez Stripa: se vedno testni nacin, da demo klubi in TestFlight delajo naprej
//   - LIVE kljuc (sk_live_), klub brez Stripa: nakup zavrnjen (409)
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
const nacinPlacila = (klub) => nacinPlacilaZ(!!(klub && klub.stripe_account_id && klub.stripe_charges_enabled));
// Vrednost za odjemalce (`payment_mode` v javnih odgovorih, #149): "test" (nic se ne zaracuna) | "stripe" (pravo placilo)
// | "unavailable" (nakup bi vrnil 409 »klub ne sprejema spletnih placil« ali 503 »placila niso nastavljena«).
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

// povratna: neobvezen { success_url, cancel_url } namesto privzetih (nakup brez racuna: success_url nosi zeton gosta, index.js).
async function ustvariCheckout({ narocilo, opis, kolicina, cenaEnoteCents, racunKluba, email, eventId, odjemalec, povratna }) {
  const s = stripe();
  const ref = encodeURIComponent(narocilo.public_ref);
  const meta = { order_id: String(narocilo.id), public_ref: narocilo.public_ref };
  return s.checkout.sessions.create({
    mode: "payment",
    client_reference_id: String(narocilo.id),
    customer_email: email || undefined,
    line_items: [{
      quantity: kolicina,
      price_data: { currency: String(narocilo.currency || "EUR").toLowerCase(), unit_amount: cenaEnoteCents, product_data: { name: opis.slice(0, 250) } },
    }],
    payment_intent_data: {
      application_fee_amount: narocilo.application_fee_cents,
      transfer_data: { destination: racunKluba },
      on_behalf_of: racunKluba,
      description: `${opis} (${narocilo.public_ref})`.slice(0, 1000),
      metadata: meta,
    },
    metadata: meta,
    expires_at: Math.floor(Date.now() / 1000) + CHECKOUT_MINUT * 60,
    ...(povratna || povratniNaslovi(odjemalec, ref, eventId)),
  }, { idempotencyKey: `outly-narocilo-${narocilo.id}` });
}

// --- obdelava dogodkov (vse v transakciji klicatelja, odjemalec c) ---

function idNarocilaIzSeje(seja) {
  const v = seja.client_reference_id || (seja.metadata && seja.metadata.order_id);
  return /^\d+$/.test(String(v || "")) ? Number(v) : null;
}

// Placilo uspelo: pending -> paid, nastanejo vstopnice. Idempotentno (drugic ne naredi nicesar).
// Vrne id narocila, ki je PRAVKAR postalo placano (sicer null): klicatelj po COMMIT-u sprozi stranske ucinke (mail gostu).
async function zakljuci(c, seja) {
  const id = idNarocilaIzSeje(seja);
  if (!id) { console.error(`[stripe] seja ${seja.id} brez narocila`); return null; }
  const r = await c.query(
    `SELECT id, public_ref, status, total_cents, currency, quantity, table_id, table_seats, event_id, stripe_checkout_session_id
       FROM orders WHERE id = $1 FOR UPDATE`, [id]);
  if (!r.rows.length) { console.error(`[stripe] seja ${seja.id}: narocila ${id} ni`); return null; }
  const o = r.rows[0];
  if (o.stripe_checkout_session_id && o.stripe_checkout_session_id !== seja.id) {
    console.error(`[stripe] seja ${seja.id} se ne ujema z narocilom ${o.public_ref} (${o.stripe_checkout_session_id})`); return null;
  }
  if (o.status !== "pending") {
    if (!["paid", "partially_refunded", "refunded"].includes(o.status)) {
      // Placilo za ze preklicano narocilo (zaloga je bila sproscena). Ne vknjizimo ga samodejno: lahko bi presegli zalogo.
      console.error(`[stripe] POZOR: placilo za neaktivno narocilo ${o.public_ref} (stanje ${o.status}, seja ${seja.id}) - vrni rocno v Stripu.`);
    }
    return null;
  }
  if (seja.amount_total !== o.total_cents || String(seja.currency || "").toUpperCase() !== String(o.currency).toUpperCase()) {
    console.error(`[stripe] POZOR: znesek seje ${seja.id} (${seja.amount_total} ${seja.currency}) != narocilo ${o.public_ref} (${o.total_cents} ${o.currency})`);
    return null;
  }
  const pi = typeof seja.payment_intent === "string" ? seja.payment_intent : (seja.payment_intent && seja.payment_intent.id) || null;
  await c.query(
    `UPDATE orders SET status = 'paid', paid_at = NOW(), stripe_payment_intent_id = $2,
            stripe_checkout_session_id = COALESCE(stripe_checkout_session_id, $3),
            -- Potrdilo kupcu z racunom (042, #95): naroceno ob prehodu v paid; gostujoce narocilo (user_id NULL) ima svoj mail (guest_mail_*).
            receipt_mail_attempts = COALESCE(receipt_mail_attempts, CASE WHEN user_id IS NOT NULL AND guest_list_id IS NULL THEN 0 END)
      WHERE id = $1`, [o.id, pi, seja.id]);
  const stevilo = o.table_id ? o.table_seats : o.quantity;
  await c.query(`INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [o.id, o.event_id, stevilo]);
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
async function posodobiKlub(c, racun) {
  await c.query(
    `UPDATE clubs SET stripe_charges_enabled = $2, stripe_payouts_enabled = $3,
            stripe_onboarded_at = CASE WHEN $4 AND stripe_onboarded_at IS NULL THEN NOW() ELSE stripe_onboarded_at END
      WHERE stripe_account_id = $1`,
    [racun.id, !!racun.charges_enabled, !!racun.payouts_enabled, !!racun.details_submitted]);
}

// Vracilo (iz Stripove nadzorne plosce ali API-ja): refunded_cents + stanje; ob polnem vracilu vstopnice `refunded`.
async function vracilo(c, charge) {
  const pi = typeof charge.payment_intent === "string" ? charge.payment_intent : (charge.payment_intent && charge.payment_intent.id);
  if (!pi) return;
  const r = await c.query("SELECT id, public_ref, total_cents, status FROM orders WHERE stripe_payment_intent_id = $1 FOR UPDATE", [pi]);
  if (!r.rows.length) return;
  const o = r.rows[0];
  if (!["paid", "partially_refunded", "refunded"].includes(o.status)) return;
  const vrnjeno = Math.min(o.total_cents, Math.max(0, Number(charge.amount_refunded) || 0));
  const polno = vrnjeno >= o.total_cents;
  await c.query("UPDATE orders SET refunded_cents = $2, status = $3, stripe_charge_id = COALESCE(stripe_charge_id, $4) WHERE id = $1",
    [o.id, vrnjeno, polno ? "refunded" : (vrnjeno > 0 ? "partially_refunded" : o.status), charge.id]);
  if (polno) await c.query("UPDATE tickets SET status = 'refunded' WHERE order_id = $1 AND status = 'valid'", [o.id]);
  console.log(`[stripe] vracilo: narocilo ${o.public_ref}, ${vrnjeno} c${polno ? " (polno)" : ""}`);
}

// Objekt dogodka preberemo SVEZ iz Stripa (pripeta API razlicica): oblika webhooka je odvisna od razlicice endpointa v
// nadzorni plosci, ne od nas, in svez objekt je tudi dodatna potrditev, da dogodek ni ponarejen.
async function svezObjekt(s, d) {
  const o = d.data && d.data.object;
  if (!o || !o.id) return o;
  if (d.type.startsWith("checkout.session.")) return s.checkout.sessions.retrieve(o.id);
  if (d.type === "charge.refunded") return s.charges.retrieve(o.id);
  if (d.type === "account.updated") return s.accounts.retrieve(o.id);
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
    default: break;   // drugi dogodki: samo zabelezeni
  }
  return null;
}

// naPlacano(idNarocila): neobvezen povratni klic PO COMMIT-u, ko narocilo postane placano (webhook ali pospravljalec). Njegova napaka
// ne sme podreti webhooka (Stripe bi ponavljal) ne pospravljalca; klicatelj jo ujame sam, tu je se varovalka.
function ustvari({ pool, naPlacano }) {
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
      return res.json({ received: true });
    } catch (e) {
      await c.query("ROLLBACK").catch(() => {});
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

module.exports = { povratniNaslovi, ustvari, stripe, jeSandbox, jeLive, testniNacin, nacinPlacila, nacinPlacilaZ, javniNacin, ustvariCheckout, osnovaSpleta, CHECKOUT_MINUT, API_VERZIJA };
