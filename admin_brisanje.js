// Pravo brisanje dogodka, kluba in promo kode v admin panelu (Martin, 24. 10. 2026; invarianta I63).
//
//   GET    /admin/api/events/:id/delete-check       predogled: ali se da izbrisati, kaj bi izginilo, kaj brisanje ustavi (samo branje, nic se ne spremeni)
//   DELETE /admin/api/events/:id        { reason }  trajno izbrise dogodek in vse odvisno
//   GET    /admin/api/clubs/:id/delete-check
//   DELETE /admin/api/clubs/:id         { reason }  trajno izbrise klub, vse njegove dogodke in vse, kar visi na klubu
//   GET    /admin/api/promo-codes/:id/delete-check
//   DELETE /admin/api/promo-codes/:id   { reason }  izbrise kodo; narocila ostanejo (orders.promo_code_id -> NULL)
//
// SAMO vloga `admin` (router `admin` v index.js: requireAuth + requireRole("admin")); zeton agenta (`outly_agent_...`) dobi 403 ze v requireAuthNa (I56), poti NISO v agent API-ju
// in NE na belem seznamu predlogov (I57). Obstojeci `DELETE /events/:id` za lastnike ostane nespremenjen (dogodek z narocili samo odpove).
//
// Zakaj je to varno pri denarju: pravi promet in davcni racuni so racunovodski dokumenti, zato brisanje ZAVRNE (409), ce dogodek (ali kateri koli dogodek kluba) ima
//   - PRAVO narocilo (ne testno: SQL_TESTNO_NAROCILO, I39; guest lista je interni vnos brez denarja in se brise), ki ni failed/cancelled (paid, partially_refunded, refunded, pending),
//   - kakrsen koli davcni racun (`racuni`, za VSA narocila),
//   - spor (`spori`), Stripovo vracilo (`vracila_iz_stripa`) ali KATERAKOLI vrstica `vracila` za PRAVO narocilo (tudi caka/v_teku/ni_uspelo/rocno: kupec utegne se cakati denar),
//   - pravo failed/cancelled narocilo s Stripovo sejo, PaymentIntentom ali paid_at (`checkout_may_complete`): kupec ga lahko se placa (I37, preveriPreklicane, webhooki 3 dni), zakljuci()
//     po brisanju narocila ne bi nasel (denar brez vstopnice in vracila). Izjema: seja dokazano mrtva (brez PI in paid_at, starejsa od 3 dni po checkout_expires_at/cancelled_at/created_at).
//   Prijave (`reports`) se NE brisejo (DECISIONS 2026-10-10 (4)).
//   Za dogodek je pravilna pot »Odpovej« (vracila gredo kupcem, narocila ostanejo). Testna narocila (lazni nacin test_<uuid>, Stripe sandbox cs_test_) in njihovi spori/vracila se brisejo.
// Klub dodatno ZAVRNE: uradni profil (`is_official`) in klub z imenom »Outly«; neodpovedan dogodek DRUGEGA kluba, ki ima ta klub za prizorisce (`venue_club_id`);
// narocilo, ki ostane (drug dogodek), a kaze na mizo/paket/guest listo kluba ali ima `club_id` tega kluba. Uporabnikov NE brise (lastnik ostane uporabnik).
//
// Transakcija: ENA, vrstice dogodkov `FOR UPDATE` PRED branjem narocil (nakup vstopnice zaklene isto vrstico v sprozilcu rezerviraj_zalogo, nakup mize in guest lista pa
// vzameta FOR KEY SHARE prek tujega kljuca, ki se s FOR UPDATE spopade): nakup, ki je ze vstavil narocilo, brisanje pocaka in ga potem vidi (409); nakup po zaklepu pade na
// tujem kljucu. Klub: vrstica kluba `FOR UPDATE` najprej (novi dogodek kluba se ne more vstaviti), nato njegovi dogodki. `SET LOCAL lock_timeout` (privzeto 3 s): zaseden
// dogodek/vstopnica (sken, ki ravno unovcuje testno vstopnico) -> 503 `busy`, NIC se ne spremeni. Sken (`skenPool`) ne dobi nobenega novega zaklepa in brisanje ga nikoli
// ne uporablja: gre samo po glavnem poolu; sken vrstice dogodka ne zaklepa (I16), unovcenje vstopnice kratko zadrzi samo to vrstico.
// Dnevnik `admin_dejanja` (event.delete_hard | club.delete | promo.delete) se vpise v ISTI transakciji: prej = osnovni podatki (brez osebnih podatkov), potem = stevila izbrisanih
// vrstic po tabelah. Razlog (3-500 znakov) je obvezen.
const express = require("express");
const { NEVIDNI } = require("./agent_predlogi");

const RAZLOG_MIN = 3, RAZLOG_NAJVEC = 500;
const okoljeMs = (ime, privzeto) => { const n = Number(process.env[ime]); return Number.isFinite(n) && n >= 1 && n <= 600000 ? Math.floor(n) : privzeto; };
const ZAKLEP_MS = okoljeMs("ADMIN_BRISANJE_ZAKLEP_MS", 3000), STAVEK_MS = okoljeMs("ADMIN_BRISANJE_STAVEK_MS", 30000);

function ustvari({ pool, celoId4, zapisiAdminDejanje, omeji, sqlTestno, poBrisanju }) {
  const r = express.Router();
  const TESTNO = sqlTestno;   // alias `o`
  const napaka = (res, status, error, message, dodatno) => res.status(status).json({ error, message, ...(dodatno || {}) });

  function razlogIzTela(req) {
    const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
    const s = typeof b.reason === "string" ? b.reason.trim() : "";
    if (s.length < RAZLOG_MIN) return { napaka: { status: 400, error: "reason_required", message: `A reason of at least ${RAZLOG_MIN} characters is required.` } };
    if ([...s].length > RAZLOG_NAJVEC) return { napaka: { status: 400, error: "reason_too_long", message: `The reason can have at most ${RAZLOG_NAJVEC} characters.` } };
    if (NEVIDNI.test(s)) return { napaka: { status: 400, error: "reason_invalid", message: "The reason contains invisible or control characters." } };
    return { razlog: s };
  }

  // Zaklep ali casovna meja -> 503 (nic spremenjeno, ponovi). Tuji kljuc (nakup je v istem trenutku vstavil vrstico) -> 409.
  function napakaBaze(res, e) {
    if (e && (e.code === "55P03" || e.code === "40P01" || e.code === "57014")) return napaka(res, 503, "busy", "The record is busy (a purchase or a scan is using it). Nothing was deleted; try again in a moment.");
    if (e && e.code === "23503") return napaka(res, 409, "changed_meanwhile", "Something was added to this record while deleting (e.g. a purchase). Nothing was deleted; check again.");
    console.error(e);
    return res.status(500).send("Server error.");
  }
  async function zacni(c) {
    await c.query("BEGIN");
    await c.query(`SET LOCAL lock_timeout = ${ZAKLEP_MS}`);
    await c.query(`SET LOCAL statement_timeout = ${STAVEK_MS}`);
  }
  const ids = (vrstice, k = "id") => vrstice.map((x) => Number(x[k]));

  // ---------------------------------------------------------------------------------------------------------------- dogodki (skupna logika dogodka in kluba)
  // Zbere VSE, kar visi na dogodkih `de` (in klubih `dk`), ter blokade. Klicati POD zaklepom vrstic dogodkov (in kluba).
  async function zberi(c, de, dk) {
    const o_ = ids((await c.query("SELECT id FROM orders WHERE event_id = ANY($1::int[]) ORDER BY id", [de])).rows);
    const op_ = o_.length ? ids((await c.query(`SELECT o.id FROM orders o WHERE o.id = ANY($1::bigint[]) AND NOT ${TESTNO}`, [o_])).rows) : [];
    const dt = ids((await c.query("SELECT id FROM tickets WHERE event_id = ANY($1::int[]) OR order_id = ANY($2::bigint[]) ORDER BY id", [de, o_])).rows);
    const gl = ids((await c.query("SELECT id FROM guest_lists WHERE event_id = ANY($1::int[]) ORDER BY id", [de])).rows);
    const mize = ids((await c.query("SELECT id FROM club_tables WHERE event_id = ANY($1::int[]) OR club_id = ANY($2::int[])", [de, dk])).rows);
    const paketi = ids((await c.query("SELECT id FROM bottle_packages WHERE club_id = ANY($1::int[])", [dk])).rows);
    const b = (await c.query(
      `SELECT
         (SELECT COALESCE(json_object_agg(s.status, s.n), '{}'::json) FROM (SELECT o.status, COUNT(*)::int AS n FROM orders o
            WHERE o.id = ANY($1::bigint[]) AND o.guest_list_id IS NULL AND o.status NOT IN ('failed','cancelled') AND NOT ${TESTNO} GROUP BY o.status) s) AS pravi,
         (SELECT COUNT(*)::int FROM racuni WHERE order_id = ANY($1::bigint[])) AS racuni,
         (SELECT COUNT(*)::int FROM spori WHERE order_id = ANY($2::bigint[])) AS spori,
         (SELECT COUNT(*)::int FROM vracila_iz_stripa WHERE order_id = ANY($2::bigint[])) AS vracila_iz_stripa,
         -- VSAKA vrstica vracila za PRAVO narocilo (caka, v_teku, ni_uspelo, rocno ...): kupec utegne se cakati denar, zato ostane (B2)
         (SELECT COUNT(*)::int FROM vracila WHERE order_id = ANY($2::bigint[])) AS vracila_pravih,
         -- pravo failed/cancelled narocilo: ce ima Stripe sejo, PI ali paid_at, ga kupec se utegne placati (I37: preveriPreklicane/zakljuci, webhooki 3 dni); zakljuci() po brisanju
         -- narocila ne bi nasel (denar pobran brez vstopnice in vracila). Izjema: seja dokazano mrtva = brez PI, brez paid_at in starejsa od 3 dni (B1).
         (SELECT COUNT(*)::int FROM orders o WHERE o.id = ANY($2::bigint[]) AND o.guest_list_id IS NULL AND o.status IN ('failed','cancelled')
            AND (o.stripe_checkout_session_id IS NOT NULL OR o.stripe_payment_intent_id IS NOT NULL OR o.paid_at IS NOT NULL)
            AND NOT (o.stripe_payment_intent_id IS NULL AND o.paid_at IS NULL AND COALESCE(o.checkout_expires_at, o.cancelled_at, o.created_at) < NOW() - INTERVAL '3 days')) AS odprta_seja,
         (SELECT COUNT(*)::int FROM orders o WHERE o.id = ANY($2::bigint[]) AND o.guest_list_id IS NULL AND o.status IN ('failed','cancelled')) AS pravi_neuspeli,
         (SELECT COUNT(*)::int FROM orders WHERE id <> ALL($1::bigint[]) AND (table_id = ANY($3::int[]) OR package_id = ANY($4::int[]) OR guest_list_id = ANY($5::bigint[]))) AS tuja_narocila,
         (SELECT COUNT(*)::int FROM orders WHERE club_id = ANY($6::int[]) AND event_id <> ALL($7::int[])) AS tuja_narocila_kluba,
         (SELECT COUNT(*)::int FROM events WHERE club_id <> ALL($6::int[]) AND venue_club_id = ANY($6::int[]) AND status <> 'cancelled') AS prizorisce,
         (SELECT COUNT(*)::int FROM clubs WHERE id = ANY($6::int[]) AND (is_official OR lower(btrim(name)) = 'outly')) AS uradni`,
      [o_, op_, mize, paketi, gl, dk, de])).rows[0];
    const blokade = [];
    const pravi = b.pravi || {};
    const praviSkupaj = Object.values(pravi).reduce((s, n) => s + Number(n), 0);
    if (b.uradni > 0) blokade.push({ code: "official_club", count: b.uradni, message: "The official Outly profile (or a club named Outly) cannot be deleted." });
    if (b.odprta_seja > 0) blokade.push({ code: "checkout_may_complete", count: b.odprta_seja,
      message: "A real cancelled or failed order still has a Stripe checkout session (or payment) that may complete (webhooks retry for 3 days). Deleting it could take a payment without a ticket or refund. Wait 3 days after it expired, or cancel the event instead." });
    if (praviSkupaj > 0) blokade.push({ code: "has_real_orders", count: praviSkupaj, by_status: pravi,
      message: "There are real (non-test) orders that are not failed or cancelled. Real sales and invoices must stay; cancel the event instead." });
    if (b.racuni > 0) blokade.push({ code: "has_invoices", count: b.racuni, message: "Tax invoices exist for orders of this event. They are accounting documents and must stay; cancel the event instead." });
    if (b.spori > 0) blokade.push({ code: "has_disputes", count: b.spori, message: "Payment disputes exist for real orders. They must stay." });
    if (b.vracila_iz_stripa > 0 || b.vracila_pravih > 0) blokade.push({ code: "has_refunds", count: b.vracila_iz_stripa + b.vracila_pravih, message: "Refunds (including queued or failed ones, or Stripe refunds) exist for real orders; a buyer may still be owed money. They must stay." });
    if (b.prizorisce > 0) blokade.push({ code: "venue_in_use", count: b.prizorisce, message: "An active event of another club uses this club as its venue. Change or cancel that event first." });
    if (b.tuja_narocila > 0 || b.tuja_narocila_kluba > 0) blokade.push({ code: "foreign_references", count: b.tuja_narocila + b.tuja_narocila_kluba,
      message: "Orders of another event point to a table, package, guest list or club that would be deleted." });
    return { de, dk, o_, op_, dt, gl, mize, paketi, blokade, pravi_neuspeli: b.pravi_neuspeli - b.odprta_seja };
  }

  // Stevila vrstic, ki jih odnese kaskada (v dnevnik in v predogled). Klicati PRED brisanjem.
  async function kaskada(c, z) {
    const x = (await c.query(
      `SELECT
         (SELECT COUNT(*)::int FROM event_tables WHERE event_id = ANY($1::int[])) AS event_tables,
         (SELECT COUNT(*)::int FROM table_holds WHERE event_id = ANY($1::int[])) AS table_holds,
         (SELECT COUNT(*)::int FROM club_tables WHERE event_id = ANY($1::int[]) OR club_id = ANY($2::int[])) AS club_tables,
         (SELECT COUNT(*)::int FROM promo_code_events WHERE event_id = ANY($1::int[])) AS promo_code_events,
         (SELECT COUNT(*)::int FROM event_favorites WHERE event_id = ANY($1::int[])) AS event_favorites,
         (SELECT COUNT(*)::int FROM event_interest WHERE event_id = ANY($1::int[])) AS event_interest,
         (SELECT COUNT(*)::int FROM club_event_notifications WHERE event_id = ANY($1::int[])) AS club_event_notifications,
         (SELECT COUNT(*)::int FROM odpovedi_dogodkov WHERE event_id = ANY($1::int[])) AS odpovedi_dogodkov,
         (SELECT COUNT(*)::int FROM view_counts WHERE event_id = ANY($1::int[]) OR club_id = ANY($2::int[])) AS view_counts,
         (SELECT COUNT(*)::int FROM table_service WHERE event_id = ANY($1::int[]) OR club_id = ANY($2::int[]) OR order_id = ANY($3::bigint[])) AS table_service,
         (SELECT COUNT(*)::int FROM vracila WHERE event_id = ANY($1::int[]) OR order_id = ANY($3::bigint[])) AS vracila,
         (SELECT COUNT(*)::int FROM spori WHERE order_id = ANY($3::bigint[])) AS spori,
         (SELECT COUNT(*)::int FROM vracila_iz_stripa WHERE order_id = ANY($3::bigint[])) AS vracila_iz_stripa,
         (SELECT COUNT(*)::int FROM gost_zetoni WHERE order_id = ANY($3::bigint[])) AS gost_zetoni,
         (SELECT COUNT(*)::int FROM ticket_transfers WHERE ticket_id = ANY($4::bigint[])) AS ticket_transfers,
         (SELECT COUNT(*)::int FROM guest_list_members WHERE ticket_id = ANY($4::bigint[]) OR guest_list_id = ANY($5::bigint[])) AS guest_list_members,
         (SELECT COUNT(*)::int FROM bottle_packages WHERE club_id = ANY($2::int[])) AS bottle_packages,
         (SELECT COUNT(*)::int FROM club_members WHERE club_id = ANY($2::int[])) AS club_members,
         (SELECT COUNT(*)::int FROM club_invites WHERE club_id = ANY($2::int[])) AS club_invites,
         (SELECT COUNT(*)::int FROM club_follows WHERE club_id = ANY($2::int[])) AS club_follows,
         (SELECT COUNT(*)::int FROM promo_codes WHERE club_id = ANY($2::int[])) AS promo_codes,
         (SELECT COUNT(*)::int FROM orders WHERE promo_code_id IN (SELECT id FROM promo_codes WHERE club_id = ANY($2::int[])) AND id <> ALL($3::bigint[])) AS orders_promo_null,
         (SELECT COUNT(*)::int FROM creator_applications WHERE club_id = ANY($2::int[])) AS creator_applications_null`,
      [z.de, z.dk, z.o_, z.dt, z.gl])).rows[0];
    return x;
  }

  // Brisanje v pravem vrstnem redu (veliko tujih kljucev je RESTRICT). Vrne stevila izbrisanih vrstic. Klicati POD zaklepi, po zberi() brez blokad.
  async function izbrisiOdvisno(c, z) {
    const n = {};
    const brisi = async (ime, sql, p, pricakovano) => {
      const x = await c.query(sql, p);
      n[ime] = x.rowCount;
      if (pricakovano !== undefined && x.rowCount !== pricakovano) throw Object.assign(new Error(`brisanje: ${ime} ${x.rowCount} namesto ${pricakovano}`), { code: "BRISANJE_NESKLADJE" });
    };
    await brisi("gost_zetoni_vstopnic", "DELETE FROM gost_zetoni_vstopnic WHERE ticket_id = ANY($1::bigint[])", [z.dt]);
    await brisi("gost_zetoni", "DELETE FROM gost_zetoni WHERE order_id = ANY($1::bigint[])", [z.o_]);
    await brisi("ticket_transfers", "DELETE FROM ticket_transfers WHERE ticket_id = ANY($1::bigint[])", [z.dt]);
    await brisi("guest_list_members", "DELETE FROM guest_list_members WHERE ticket_id = ANY($1::bigint[]) OR guest_list_id = ANY($2::bigint[])", [z.dt, z.gl]);
    await brisi("tickets", "DELETE FROM tickets WHERE id = ANY($1::bigint[])", [z.dt], z.dt.length);
    await brisi("vracila_iz_stripa", "DELETE FROM vracila_iz_stripa WHERE order_id = ANY($1::bigint[])", [z.o_]);
    await brisi("spori", "DELETE FROM spori WHERE order_id = ANY($1::bigint[])", [z.o_]);
    await brisi("vracila", "DELETE FROM vracila WHERE order_id = ANY($1::bigint[]) OR event_id = ANY($2::int[])", [z.o_, z.de]);
    await brisi("table_service", "DELETE FROM table_service WHERE order_id = ANY($1::bigint[]) OR event_id = ANY($2::int[]) OR club_id = ANY($3::int[])", [z.o_, z.de, z.dk]);
    await brisi("orders", "DELETE FROM orders WHERE id = ANY($1::bigint[])", [z.o_], z.o_.length);
    await brisi("guest_lists", "DELETE FROM guest_lists WHERE id = ANY($1::bigint[])", [z.gl], z.gl.length);
    // Prijave (reports) se NE brisejo (DECISIONS 2026-10-10 (4)): prijava o izbrisanem cilju ostane kot dokaz (target_label null; tujega kljuca ni).
    // Odprt predlog agenta za izbrisan dogodek/klub bi v panelu cakal na klik, ki bi padel: potece (kot migracija 066).
    await brisi("predlogi_dejanj_potekli",
      `UPDATE predlogi_dejanj SET stanje = 'potekel', odloceno_at = NOW(), napaka = 'Event or club was deleted by an admin'
        WHERE stanje = 'caka' AND ((cilj_tip = 'event' AND cilj_id = ANY($1::int[])) OR (cilj_tip = 'club' AND cilj_id = ANY($2::int[])))`, [z.de, z.dk]);
    // Naslednje vrstice odnese kaskada (event_tables, table_holds, club_tables dogodka, promo_code_events, favoriti, zanimanje, ogledi, odpovedi_dogodkov ...); stevilo je v `kaskada`.
    await brisi("events", "DELETE FROM events WHERE id = ANY($1::int[])", [z.de], z.de.length);
    return n;
  }

  const odgovorBlokad = (res, z, sporocilo) => napaka(res, 409, z.blokade[0].code, sporocilo || z.blokade[0].message, { blockers: z.blokade });
  const zaDnevnik = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => Number(v) > 0));

  // ---------------------------------------------------------------------------------------------------------------------------------------------- dogodek
  async function nalozi(c, id) {
    return (await c.query(
      `SELECT e.id, e.club_id, e.title, e.status, e.start_at, e.ticket_price_cents, e.currency, e.sold_count, cl.name AS club_name
         FROM events e JOIN clubs cl ON cl.id = e.club_id WHERE e.id = $1`, [id])).rows[0];
  }
  const prejDogodka = (e) => ({ title: e.title, club_id: e.club_id, club_name: e.club_name, status: e.status, start_at: e.start_at instanceof Date ? e.start_at.toISOString() : e.start_at,
    ticket_price_cents: e.ticket_price_cents, currency: e.currency, sold_count: e.sold_count });

  r.get("/events/:id/delete-check", async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return napaka(res, 400, "invalid_id", "Invalid event id.");
    const c = await pool.connect();
    try {
      await c.query("BEGIN READ ONLY");
      await c.query(`SET LOCAL statement_timeout = ${STAVEK_MS}`);
      const e = await nalozi(c, id);
      if (!e) { await c.query("ROLLBACK"); return napaka(res, 404, "not_found", "Event not found."); }
      const z = await zberi(c, [id], []);
      const lite = req.query.lite === "1";   // samo blokade (panel ob odprtju dogodka); polni predogled s kaskado sele ob kliku »Izbrisi« (P2)
      const k = lite ? null : await kaskada(c, z);
      await c.query("ROLLBACK");
      return res.json({ can_delete: z.blokade.length === 0, event: { id: e.id, title: e.title, status: e.status, club_name: e.club_name }, blockers: z.blokade,
        ...(lite ? { lite: true } : { will_delete: { orders: z.o_.length, real_failed_orders: z.pravi_neuspeli, tickets: z.dt.length, guest_lists: z.gl.length, ...k } }) });
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); return napakaBaze(res, e); }
    finally { c.release(); }
  });

  r.delete("/events/:id", omeji, async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return napaka(res, 400, "invalid_id", "Invalid event id.");
    const rz = razlogIzTela(req);
    if (rz.napaka) return napaka(res, rz.napaka.status, rz.napaka.error, rz.napaka.message);
    const c = await pool.connect();
    try {
      await zacni(c);
      const l = (await c.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [id])).rows[0];
      if (!l) { await c.query("ROLLBACK"); return napaka(res, 404, "not_found", "Event not found."); }
      const e = await nalozi(c, id);
      const z = await zberi(c, [id], []);
      if (z.blokade.length) { await c.query("ROLLBACK"); return odgovorBlokad(res, z); }
      const k = await kaskada(c, z);
      const n = await izbrisiOdvisno(c, z);
      await zapisiAdminDejanje(c, req, "event.delete_hard", "event", id, prejDogodka(e), { deleted: zaDnevnik({ ...n, ...k }), real_failed_orders: z.pravi_neuspeli }, rz.razlog);
      await c.query("COMMIT");
      poBrisanju({ eventIds: [id] });
      console.log(`Admin ${req.user.userId} je TRAJNO izbrisal dogodek ${id} (${n.orders} testnih/neuspelih narocil, ${n.tickets} vstopnic)`);
      return res.json({ deleted: true, event_id: id, real_failed_orders: z.pravi_neuspeli, counts: zaDnevnik({ ...n, ...k }) });
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); return napakaBaze(res, e); }
    finally { c.release(); }
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------------ klub
  async function naloziKlub(c, id) {
    return (await c.query("SELECT id, name, city, hidden, is_demo, is_official, is_organizer FROM clubs WHERE id = $1", [id])).rows[0];
  }
  async function dogodkiKluba(c, id) {
    return (await c.query("SELECT id, title, status, start_at FROM events WHERE club_id = $1 ORDER BY id", [id])).rows;
  }

  r.get("/clubs/:id/delete-check", async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return napaka(res, 400, "invalid_id", "Invalid club id.");
    const c = await pool.connect();
    try {
      await c.query("BEGIN READ ONLY");
      await c.query(`SET LOCAL statement_timeout = ${STAVEK_MS}`);
      const k = await naloziKlub(c, id);
      if (!k) { await c.query("ROLLBACK"); return napaka(res, 404, "not_found", "Club not found."); }
      const dog = await dogodkiKluba(c, id);
      const z = await zberi(c, dog.map((x) => x.id), [id]);
      const lite = req.query.lite === "1";
      const kas = lite ? null : await kaskada(c, z);
      await c.query("ROLLBACK");
      return res.json({ can_delete: z.blokade.length === 0, club: { id: k.id, name: k.name, city: k.city, is_official: k.is_official }, blockers: z.blokade,
        events: dog.slice(0, 50).map((x) => ({ id: x.id, title: x.title, status: x.status, start_at: x.start_at })), events_total: dog.length,
        ...(lite ? { lite: true } : { will_delete: { events: dog.length, orders: z.o_.length, real_failed_orders: z.pravi_neuspeli, tickets: z.dt.length, guest_lists: z.gl.length, ...kas } }) });
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); return napakaBaze(res, e); }
    finally { c.release(); }
  });

  r.delete("/clubs/:id", omeji, async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return napaka(res, 400, "invalid_id", "Invalid club id.");
    const rz = razlogIzTela(req);
    if (rz.napaka) return napaka(res, rz.napaka.status, rz.napaka.error, rz.napaka.message);
    const c = await pool.connect();
    try {
      await zacni(c);
      const l = (await c.query("SELECT id FROM clubs WHERE id = $1 FOR UPDATE", [id])).rows[0];   // najprej klub (novi dogodek kluba se ne more vstaviti), nato dogodki
      if (!l) { await c.query("ROLLBACK"); return napaka(res, 404, "not_found", "Club not found."); }
      const k = await naloziKlub(c, id);
      const dog = await dogodkiKluba(c, id);
      if (dog.length) await c.query("SELECT id FROM events WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE", [dog.map((x) => x.id)]);
      const z = await zberi(c, dog.map((x) => x.id), [id]);
      if (z.blokade.length) { await c.query("ROLLBACK"); return odgovorBlokad(res, z); }
      const kas = await kaskada(c, z);
      const n = await izbrisiOdvisno(c, z);
      // Narocila drugih dogodkov, ki so uporabila kodo kluba (ne bi smela obstajati; koda velja za dogodke kluba): promo_code_id -> NULL, narocilo ostane.
      const pn = await c.query("UPDATE orders SET promo_code_id = NULL WHERE promo_code_id IN (SELECT id FROM promo_codes WHERE club_id = $1)", [id]);
      n.orders_promo_null = pn.rowCount;
      const cr = await c.query("DELETE FROM clubs WHERE id = $1", [id]);
      if (cr.rowCount !== 1) throw Object.assign(new Error("brisanje: klub"), { code: "BRISANJE_NESKLADJE" });
      await zapisiAdminDejanje(c, req, "club.delete", "club", id,
        { name: k.name, city: k.city, hidden: k.hidden, is_demo: k.is_demo, is_organizer: k.is_organizer, events: dog.slice(0, 100).map((x) => ({ id: x.id, title: x.title, status: x.status })), events_total: dog.length },
        { deleted: zaDnevnik({ events: n.events, ...n, ...kas, clubs: 1 }), real_failed_orders: z.pravi_neuspeli }, rz.razlog);
      await c.query("COMMIT");
      poBrisanju({ eventIds: z.de, clubId: id });
      console.log(`Admin ${req.user.userId} je TRAJNO izbrisal klub ${id} (${dog.length} dogodkov, ${n.orders} testnih/neuspelih narocil)`);
      return res.json({ deleted: true, club_id: id, counts: zaDnevnik({ clubs: 1, ...n, ...kas }) });
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); return napakaBaze(res, e); }
    finally { c.release(); }
  });

  // -------------------------------------------------------------------------------------------------------------------------------------------- promo koda
  r.get("/promo-codes/:id/delete-check", async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return napaka(res, 400, "invalid_id", "Invalid promo code id.");
    try {
      const k = (await pool.query("SELECT id, code, label, active FROM promo_codes WHERE id = $1", [id])).rows[0];
      if (!k) return napaka(res, 404, "not_found", "Promo code not found.");
      const s = (await pool.query(
        `SELECT (SELECT COUNT(*)::int FROM orders WHERE promo_code_id = $1) AS orders,
                (SELECT COUNT(*)::int FROM promo_code_events WHERE promo_code_id = $1) AS promo_code_events`, [id])).rows[0];
      return res.json({ can_delete: true, promo_code: k, blockers: [], will_delete: { promo_codes: 1, promo_code_events: s.promo_code_events }, orders_using_code: s.orders });
    } catch (e) { return napakaBaze(res, e); }
  });

  r.delete("/promo-codes/:id", omeji, async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return napaka(res, 400, "invalid_id", "Invalid promo code id.");
    const rz = razlogIzTela(req);
    if (rz.napaka) return napaka(res, rz.napaka.status, rz.napaka.error, rz.napaka.message);
    const c = await pool.connect();
    try {
      await zacni(c);
      // FOR UPDATE: nakup, ki je kodo ze vezal (FOR KEY SHARE prek tujega kljuca), brisanje pocaka in ga UPDATE spodaj ze vidi; poznejsi nakup pade na tujem kljucu.
      const k = (await c.query("SELECT id, code, label, active, club_id FROM promo_codes WHERE id = $1 FOR UPDATE", [id])).rows[0];
      if (!k) { await c.query("ROLLBACK"); return napaka(res, 404, "not_found", "Promo code not found."); }
      const dogodki = ids((await c.query("SELECT event_id FROM promo_code_events WHERE promo_code_id = $1 ORDER BY event_id", [id])).rows, "event_id");
      const u = await c.query("UPDATE orders SET promo_code_id = NULL WHERE promo_code_id = $1", [id]);   // naroceni ostanejo, samo vez s kodo izgine (orders_promo_code_id_fkey je brez ON DELETE)
      const d = await c.query("DELETE FROM promo_codes WHERE id = $1", [id]);   // promo_code_events: ON DELETE CASCADE
      if (d.rowCount !== 1) throw Object.assign(new Error("brisanje: promo koda"), { code: "BRISANJE_NESKLADJE" });
      await zapisiAdminDejanje(c, req, "promo.delete", "promo_code", id,
        { code: k.code, label: k.label, active: k.active, club_id: k.club_id, event_ids: dogodki.slice(0, 200) },
        { deleted: zaDnevnik({ promo_codes: 1, promo_code_events: dogodki.length }), orders_detached: u.rowCount }, rz.razlog);
      await c.query("COMMIT");
      poBrisanju({});
      console.log(`Admin ${req.user.userId} je TRAJNO izbrisal promo kodo ${id} (${u.rowCount} narocil odvezanih)`);
      return res.json({ deleted: true, promo_code_id: id, orders_detached: u.rowCount, counts: zaDnevnik({ promo_codes: 1, promo_code_events: dogodki.length }) });
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); return napakaBaze(res, e); }
    finally { c.release(); }
  });

  return r;
}

module.exports = { ustvari };
