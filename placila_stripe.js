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
//   - brez STRIPE_SECRET_KEY ali TEST_PLACILA=true: testni nacin kot doslej (takoj `paid`, oznaka test_)
//   - klub z dokoncanim Connect onboardingom (charges_enabled): Stripe
//   - SANDBOX kljuc (sk_test_), klub brez Stripa: se vedno testni nacin, da demo klubi in TestFlight delajo naprej
//   - LIVE kljuc (sk_live_), klub brez Stripa: nakup zavrnjen (409)
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
const webhookSkrivnosti = () => [process.env.STRIPE_WEBHOOK_SECRET, process.env.STRIPE_CONNECT_WEBHOOK_SECRET].filter(Boolean);
const osnovaSpleta = () => (process.env.APP_URL || "https://outly.si").replace(/\/+$/, "");

// "test" | "stripe" | "nastavitve" (kljuc brez webhook skrivnosti -> 503) | "klub" (live, klub brez Stripa -> 409)
function nacinPlacila(klub) {
  if (process.env.TEST_PLACILA === "true") return "test";
  if (!process.env.STRIPE_SECRET_KEY) return "test";
  if (!process.env.STRIPE_WEBHOOK_SECRET) return "nastavitve";
  if (klub && klub.stripe_account_id && klub.stripe_charges_enabled) return "stripe";
  return jeSandbox() ? "test" : "klub";
}

// Checkout seja za narocilo. Klicatelj narocilo ze ima (pending, v bazi). Vrne sejo ali vrze napako.
async function ustvariCheckout({ narocilo, opis, kolicina, cenaEnoteCents, racunKluba, email, eventId }) {
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
    success_url: `${osnovaSpleta()}/app/tickets?placilo=uspeh&narocilo=${ref}`,
    cancel_url: `${osnovaSpleta()}/app/event/${eventId}?placilo=preklic&narocilo=${ref}`,
  }, { idempotencyKey: `outly-narocilo-${narocilo.id}` });
}

// --- obdelava dogodkov (vse v transakciji klicatelja, odjemalec c) ---

function idNarocilaIzSeje(seja) {
  const v = seja.client_reference_id || (seja.metadata && seja.metadata.order_id);
  return /^\d+$/.test(String(v || "")) ? Number(v) : null;
}

// Placilo uspelo: pending -> paid, nastanejo vstopnice. Idempotentno (drugic ne naredi nicesar).
async function zakljuci(c, seja) {
  const id = idNarocilaIzSeje(seja);
  if (!id) { console.error(`[stripe] seja ${seja.id} brez narocila`); return; }
  const r = await c.query(
    `SELECT id, public_ref, status, total_cents, currency, quantity, table_id, table_seats, event_id, stripe_checkout_session_id
       FROM orders WHERE id = $1 FOR UPDATE`, [id]);
  if (!r.rows.length) { console.error(`[stripe] seja ${seja.id}: narocila ${id} ni`); return; }
  const o = r.rows[0];
  if (o.stripe_checkout_session_id && o.stripe_checkout_session_id !== seja.id) {
    console.error(`[stripe] seja ${seja.id} se ne ujema z narocilom ${o.public_ref} (${o.stripe_checkout_session_id})`); return;
  }
  if (o.status !== "pending") {
    if (!["paid", "partially_refunded", "refunded"].includes(o.status)) {
      // Placilo za ze preklicano narocilo (zaloga je bila sproscena). Ne vknjizimo ga samodejno: lahko bi presegli zalogo.
      console.error(`[stripe] POZOR: placilo za neaktivno narocilo ${o.public_ref} (stanje ${o.status}, seja ${seja.id}) - vrni rocno v Stripu.`);
    }
    return;
  }
  if (seja.amount_total !== o.total_cents || String(seja.currency || "").toUpperCase() !== String(o.currency).toUpperCase()) {
    console.error(`[stripe] POZOR: znesek seje ${seja.id} (${seja.amount_total} ${seja.currency}) != narocilo ${o.public_ref} (${o.total_cents} ${o.currency})`);
    return;
  }
  const pi = typeof seja.payment_intent === "string" ? seja.payment_intent : (seja.payment_intent && seja.payment_intent.id) || null;
  await c.query(
    `UPDATE orders SET status = 'paid', paid_at = NOW(), stripe_payment_intent_id = $2,
            stripe_checkout_session_id = COALESCE(stripe_checkout_session_id, $3)
      WHERE id = $1`, [o.id, pi, seja.id]);
  const stevilo = o.table_id ? o.table_seats : o.quantity;
  await c.query(`INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [o.id, o.event_id, stevilo]);
  console.log(`[stripe] placano: narocilo ${o.public_ref}, ${stevilo} vstopnic`);
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

async function obdelajDogodek(c, d, o) {
  switch (d.type) {
    case "checkout.session.completed":
      if (o.payment_status === "paid") await zakljuci(c, o);   // "unpaid" = odlozeno placilo, pride async_payment_succeeded
      break;
    case "checkout.session.async_payment_succeeded": await zakljuci(c, o); break;
    case "checkout.session.expired": await prekini(c, o, "cancelled"); break;
    case "checkout.session.async_payment_failed": await prekini(c, o, "failed"); break;
    case "account.updated": await posodobiKlub(c, o); break;
    case "charge.refunded": await vracilo(c, o); break;
    default: break;   // drugi dogodki: samo zabelezeni
  }
}

function ustvari({ pool }) {
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
      await obdelajDogodek(c, d, objekt);
      await c.query("COMMIT");
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
          ORDER BY created_at LIMIT 50`);
      for (const o of r.rows) {
        try {
          if (!o.stripe_checkout_session_id) {
            await pool.query("UPDATE orders SET status = 'failed', cancelled_at = NOW() WHERE id = $1 AND status = 'pending'", [o.id]);
            console.log(`[stripe] pospravljeno: narocilo ${o.public_ref} brez seje -> failed`);
            continue;
          }
          let seja = await s.checkout.sessions.retrieve(o.stripe_checkout_session_id);
          if (seja.status === "open") seja = await s.checkout.sessions.expire(seja.id);
          if (seja.status === "complete" && seja.payment_status === "paid") await vTransakciji((c) => zakljuci(c, seja));
          else if (seja.status === "expired") await vTransakciji((c) => prekini(c, seja, "cancelled"));
          // complete + unpaid: odlozeno placilo, pocakaj na async webhook
        } catch (e) { console.error(`[stripe] pospravljanje narocila ${o.public_ref}:`, e.message); }
      }
    } catch (e) { console.error("[stripe] pospravljanje:", e.message); }
    finally { tece = false; }
  }

  function zazeni() {
    if (!process.env.STRIPE_SECRET_KEY) return;
    if (!process.env.STRIPE_WEBHOOK_SECRET) console.error("OPOZORILO: STRIPE_SECRET_KEY je nastavljen, STRIPE_WEBHOOK_SECRET pa ne - Stripe nakupi vracajo 503.");
    console.log(`[stripe] vklopljen (${jeSandbox() ? "SANDBOX" : "LIVE"}), API ${API_VERZIJA}`);
    setInterval(() => { pospravi(); }, Number(process.env.STRIPE_POSPRAVI_MS) || POSPRAVI_MS).unref();
  }

  return { webhook, pospravi, zazeni };
}

module.exports = { ustvari, stripe, jeSandbox, nacinPlacila, ustvariCheckout, osnovaSpleta, CHECKOUT_MINUT, API_VERZIJA };
