#!/usr/bin/env node
/**
 * Varovala odpovedi dogodka (#255 KRITICNO, invarianta I42; #258 N2). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_odpoved_minilega.js
 * Vsi casi so relativni na zdaj (brez fiksnih datumov). Obdelovalec vracil je izklopljen (VRACILA_TICK_MS=0, sweep 0): test bere samo vrstice `vracila`.
 *
 *   1  Lastnik/manager: odpoved (DELETE in PATCH status cancelled) dogodka s placanimi narocili, ki je MINIL (end_at < zdaj; brez end_at: start + 18 h < zdaj)
 *      ali ima UNOVCENO vstopnico -> 409 { error: "event_finished", message } (sporocilo z »already started«: star iOS/splet ga prevedeta); nic v `vracila`,
 *      dogodek ni odpovedan, ni vrstice v odpovedi_dogodkov
 *   2  Meje: brez end_at start - 17 h = se ni minil (odpoved dela); end_at pred 1 h (okno skena se odprto) = minil
 *   3  Premik datuma minilega dogodka s placanimi narocili -> 409 (sicer: premakni v prihodnost, nato odpovej); isti datum (obrazec ga poslje vedno) in druga polja delajo
 *   4  Prihodnji dogodek: odpoved kot prej (refunds_queued); ze odpovedan dogodek PATCH status cancelled (splet ga poslje znova) -> 200
 *   5  Admin (vloga iz baze) sme: DELETE /events/:id in admin panel PATCH /admin/api/events/:id
 *   6  Brez placanih narocil: prazen dogodek se izbrise kot doslej (tudi minil); #258 N2: samo pending/preklicana/vrnjena narocila -> 200 odpoved
 *      brez vracil (prej 500, FK orders_event_id_fkey), dogodek zabelezen v odpovedi_dogodkov (sweep vrne pozno placilo)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("Manjka DATABASE_URL"); process.exit(1); }
const PORT = 4681, JWKS_PORT = 4682;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-odpoved";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});
function b64u(o) { return Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url"); }
function zeton(email, sub) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${JWKS_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now,
    user_metadata: { email_verified: true, username: email.split("@")[0].replace(/[^a-z0-9_]/gi, "") } });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
const URA = 3600 * 1000;

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, vracila, odpovedi_dogodkov, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "", RESEND_API_KEY: "", JAVNI_PREDPOMNILNIK_MS: "0", VRACILA_TICK_MS: "0", VRACILA_SWEEP_MS: "0" },
    stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", x => log += x); srv.stderr.on("data", x => log += x);
  for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  try {
    const imena = ["lastnik", "manager", "admin", "ana"];
    const T = {}, U = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','manager@outly.si')");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, address, contact_phone, contact_email) VALUES ($1, 'Varovala Club', 'Ljubljana', 'Slovenska 1', '+38640111222', 'info@varovala.si')", [U.lastnik]);
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, $1, 'manager')", [U.manager]);

    const cezDan = new Date(Date.now() + 24 * URA).toISOString();
    // Dogodek nastane prek API-ja (prihodnost), cas se nato premakne v bazi relativno na zdaj.
    const dogodek = async (title, zacetekMs, konecMs = null) => {
      const r = await api("POST", "/events", T.lastnik, { clubId: 1, title, startAt: cezDan, ticketPriceCents: 2000, capacity: 500, minAge: 0 });
      assert(r.status === 201, `dogodek ${title}`, r.body);
      await pool.query("UPDATE events SET start_at = NOW() + ($2::bigint * INTERVAL '1 millisecond'), end_at = CASE WHEN $3::bigint IS NULL THEN NULL ELSE NOW() + ($3::bigint * INTERVAL '1 millisecond') END WHERE id = $1",
        [r.body.id, zacetekMs, konecMs]);
      return r.body.id;
    };
    let stRef = 0;
    const narocilo = async (ev, status = "paid") => {
      const ref = "OUT-OD" + String(++stRef).padStart(4, "0");
      const r = await pool.query(
        `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, stripe_payment_intent_id, buyer_email, paid_at, cancelled_at, refunded_cents)
         VALUES ($1, $2, $3, 1, 1, 2000, 2000, 'EUR', 200, $4, $5, 'ana@outly.si', CASE WHEN $4 IN ('paid','refunded') THEN NOW() - INTERVAL '3 days' END,
                 CASE WHEN $4 IN ('cancelled','failed') THEN NOW() END, CASE WHEN $4 = 'refunded' THEN 2000 ELSE 0 END) RETURNING id`,
        [ref, U.ana, ev, status, "test_" + ref.replace("-", "")]);
      const id = r.rows[0].id;
      if (status === "paid") await pool.query("INSERT INTO tickets (order_id, event_id) VALUES ($1, $2)", [id, ev]);
      if (status === "refunded") await pool.query("INSERT INTO tickets (order_id, event_id, status) VALUES ($1, $2, 'refunded')", [id, ev]);
      return id;
    };
    const vracilaDogodka = async (ev) => (await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE event_id = $1", [ev])).rows[0].n;
    const stanje = async (ev) => { const x = (await pool.query("SELECT status FROM events WHERE id = $1", [ev])).rows[0]; return x ? x.status : null; };
    const zabelezen = async (ev) => (await pool.query("SELECT 1 FROM odpovedi_dogodkov WHERE event_id = $1", [ev])).rows.length === 1;
    const ZAVRNJENO = { error: "event_finished", message: "This event has already started or taken place, so it can't be cancelled. Contact Outly for refunds." };
    const jeZavrnjeno = (r) => r.status === 409 && r.body && r.body.error === ZAVRNJENO.error && r.body.message === ZAVRNJENO.message;
    const nedotaknjen = async (ev, opis) => {
      assert(await stanje(ev) === "published", `${opis}: dogodek ostane objavljen`, await stanje(ev));
      assert(await vracilaDogodka(ev) === 0, `${opis}: ni vrstic v vracila`);
      assert(!(await zabelezen(ev)), `${opis}: ni vrstice v odpovedi_dogodkov (sweep ga ne bo vracal)`);
    };

    // ================================================================
    console.log("\n# 1. Minil dogodek s placanimi narocili: lastnik/manager -> 409, brez vracil");
    const evMinil = await dogodek("Minila noc", -50 * URA, -44 * URA);
    await narocilo(evMinil); await narocilo(evMinil);
    let r = await api("DELETE", `/events/${evMinil}`, T.lastnik);
    assert(jeZavrnjeno(r), "DELETE lastnik: 409 event_finished z natancnim sporocilom", r);
    assert(/already started/i.test(r.body.message || ""), "sporocilo vsebuje »already started« (star iOS APIErrorMessages in splet napake.js ga prevedeta)");
    r = await api("DELETE", `/events/${evMinil}`, T.manager);
    assert(jeZavrnjeno(r), "DELETE manager: 409 event_finished", r);
    r = await api("PATCH", `/events/${evMinil}`, T.lastnik, { status: "cancelled" });
    assert(jeZavrnjeno(r), "PATCH status cancelled lastnik: 409 event_finished", r);
    r = await api("PATCH", `/events/${evMinil}`, T.manager, { status: "cancelled", title: "Minila noc 2" });
    assert(jeZavrnjeno(r), "PATCH status cancelled + naslov, manager: 409 (nic se ne zapise)", r);
    assert((await pool.query("SELECT title FROM events WHERE id=$1", [evMinil])).rows[0].title === "Minila noc", "PATCH z odpovedjo zavrnjen v celoti (naslov ni spremenjen)");
    await nedotaknjen(evMinil, "minil");

    // Brez end_at: konec = start + 18 h (konec okna skena I25)
    const evBrez19 = await dogodek("Brez konca pred 19 h", -19 * URA);
    await narocilo(evBrez19);
    r = await api("DELETE", `/events/${evBrez19}`, T.lastnik);
    assert(jeZavrnjeno(r), "brez end_at, start pred 19 h: 409", r);
    await nedotaknjen(evBrez19, "brez end_at 19 h");

    // ================================================================
    console.log("\n# 2. Meje okna");
    const evBrez17 = await dogodek("Brez konca pred 17 h", -17 * URA);
    await narocilo(evBrez17);
    r = await api("DELETE", `/events/${evBrez17}`, T.lastnik);
    assert(r.status === 200 && r.body.event && r.body.event.status === "cancelled" && r.body.refunds_queued === 1, "brez end_at, start pred 17 h (brez unovcenih): se sme odpovedati, vracilo v vrsti", r.body);
    const evKonec1h = await dogodek("Koncan pred 1 h", -5 * URA, -1 * URA);
    await narocilo(evKonec1h);
    r = await api("PATCH", `/events/${evKonec1h}`, T.lastnik, { status: "cancelled" });
    assert(jeZavrnjeno(r), "end_at pred 1 h (sken se odprt +6 h): ze minil -> 409", r);
    await nedotaknjen(evKonec1h, "end_at pred 1 h");

    // ================================================================
    console.log("\n# 1b. Unovcena vstopnica (gost je ze vstopil): 409 tudi za dogodek, ki se ni minil");
    const evUsed = await dogodek("Tece z unovceno", 2 * URA, 8 * URA);
    const oUsed = await narocilo(evUsed); await narocilo(evUsed);
    await pool.query("UPDATE tickets SET status='used', used_at=NOW() WHERE order_id=$1", [oUsed]);
    r = await api("DELETE", `/events/${evUsed}`, T.lastnik);
    assert(jeZavrnjeno(r), "DELETE dogodka z `used` vstopnico: 409", r);
    r = await api("PATCH", `/events/${evUsed}`, T.manager, { status: "cancelled" });
    assert(jeZavrnjeno(r), "PATCH cancelled dogodka z `used` vstopnico: 409", r);
    await nedotaknjen(evUsed, "used");
    r = await api("PATCH", `/events/${evUsed}`, T.lastnik, { endAt: new Date(Date.now() + 10 * URA).toISOString() });
    assert(r.status === 200, "dogodek, ki tece (unovcene, ni minil): podaljsanje end_at dela", r.body);

    // ================================================================
    console.log("\n# 3. Premik datuma minilega dogodka");
    const zacetekMinil = (await pool.query("SELECT start_at, end_at FROM events WHERE id=$1", [evMinil])).rows[0];
    r = await api("PATCH", `/events/${evMinil}`, T.lastnik, { startAt: cezDan, endAt: null });
    assert(r.status === 409 && r.body.error === "event_finished" && /already started/.test(r.body.message), "premik minilega dogodka v prihodnost: 409 event_finished", r);
    r = await api("PATCH", `/events/${evMinil}`, T.lastnik, { endAt: new Date(Date.now() + 2 * URA).toISOString() });
    assert(r.status === 409 && r.body.error === "event_finished", "podaljsanje end_at minilega dogodka v prihodnost: 409", r);
    r = await api("PATCH", `/events/${evMinil}`, T.lastnik, { title: "Minila noc (urejeno)", startAt: new Date(zacetekMinil.start_at).toISOString(), endAt: new Date(zacetekMinil.end_at).toISOString(), status: "published" });
    assert(r.status === 200 && r.body.title === "Minila noc (urejeno)", "obrazec z ISTIM datumom (iOS/splet ga poslje vedno) + naslov: 200", r.body);
    r = await api("PATCH", `/events/${evMinil}`, T.lastnik, { description: "Hvala vsem!" });
    assert(r.status === 200, "minil dogodek: urejanje opisa dela", r.body);
    await nedotaknjen(evMinil, "minil po urejanju");

    // ================================================================
    console.log("\n# 4. Prihodnji dogodek: odpoved kot prej");
    const evPrihodnji = await dogodek("Prihodnja noc", 24 * URA, 30 * URA);
    await narocilo(evPrihodnji); await narocilo(evPrihodnji);
    r = await api("DELETE", `/events/${evPrihodnji}`, T.manager);
    assert(r.status === 200 && r.body.message === "Event has sold tickets and was cancelled instead of deleted." && r.body.orders === 2 && r.body.refunds_queued === 2 && r.body.event.status === "cancelled",
      "DELETE prihodnjega: odpovedan, 2 vracili v vrsti (oblika odgovora kot prej)", r.body);
    assert(await vracilaDogodka(evPrihodnji) === 2 && await zabelezen(evPrihodnji), "vracila v bazi + odpovedi_dogodkov");
    const evPrihodnjiP = await dogodek("Prihodnja noc PATCH", 24 * URA);
    await narocilo(evPrihodnjiP);
    r = await api("PATCH", `/events/${evPrihodnjiP}`, T.lastnik, { status: "cancelled" });
    assert(r.status === 200 && r.body.status === "cancelled", "PATCH status cancelled prihodnjega: 200 (vracila potem sweep, I37)", r.body);
    // Ze odpovedan dogodek, ki je medtem minil: splet ob urejanju poslje status cancelled znova -> ni nova odpoved, 200
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '3 days', end_at = NULL WHERE id = $1", [evPrihodnjiP]);
    r = await api("PATCH", `/events/${evPrihodnjiP}`, T.lastnik, { status: "cancelled", description: "Odpovedano." });
    assert(r.status === 200 && r.body.status === "cancelled", "ze odpovedan (minil) dogodek: PATCH status cancelled + opis = 200 (ni prehoda)", r.body);

    // ================================================================
    console.log("\n# 5. Admin sme");
    r = await api("DELETE", `/events/${evBrez19}`, T.admin);
    assert(r.status === 200 && r.body.event && r.body.event.status === "cancelled" && r.body.refunds_queued === 1, "admin DELETE minilega dogodka: odpovedan, vracilo v vrsti", r.body);
    r = await api("PATCH", `/events/${evKonec1h}`, T.admin, { status: "cancelled" });
    assert(r.status === 200 && r.body.status === "cancelled", "admin PATCH /events/:id status cancelled minilega: 200", r.body);
    r = await api("PATCH", `/admin/api/events/${evUsed}`, T.admin, { status: "cancelled" });
    assert(r.status === 200 && r.body.status === "cancelled", "admin panel PATCH /admin/api/events/:id (z unovceno vstopnico): 200", r.body);
    r = await api("PATCH", `/admin/api/events/${evUsed}`, T.lastnik, { status: "published" });
    assert(r.status === 403 || r.status === 401, "admin panel pot ni za lastnika", r.status);
    assert(/Admin \d+ je odpovedal dogodek/.test(log), "admin odpoved prek /events/:id je v dnevniku");

    // ================================================================
    console.log("\n# 6. Brez placanih narocil (#258 N2)");
    const evPrazen = await dogodek("Prazna minila", -72 * URA);
    r = await api("DELETE", `/events/${evPrazen}`, T.lastnik);
    assert(r.status === 200 && r.body.message === "Event deleted." && await stanje(evPrazen) === null, "minil dogodek brez narocil: izbris kot doslej", r.body);
    const evNeplacan = await dogodek("Samo neplacana", 24 * URA);
    await narocilo(evNeplacan, "pending"); await narocilo(evNeplacan, "cancelled"); await narocilo(evNeplacan, "failed"); await narocilo(evNeplacan, "refunded");
    r = await api("DELETE", `/events/${evNeplacan}`, T.lastnik);
    assert(r.status === 200 && r.body.message === "Event has orders and was cancelled instead of deleted." && r.body.orders === 0 && r.body.refunds_queued === 0 && r.body.event && r.body.event.status === "cancelled",
      "pending/preklicana/vrnjena narocila: 200 odpoved brez vracil (prej 500 FK)", r.body);
    assert(await stanje(evNeplacan) === "cancelled" && await vracilaDogodka(evNeplacan) === 0 && await zabelezen(evNeplacan), "dogodek ostane (narocila so dokument), 0 vracil, zabelezen v odpovedi_dogodkov");
    const evNeplacanMinil = await dogodek("Neplacana minila", -72 * URA);
    await narocilo(evNeplacanMinil, "cancelled");
    r = await api("DELETE", `/events/${evNeplacanMinil}`, T.manager);
    assert(r.status === 200 && r.body.event && r.body.event.status === "cancelled" && r.body.refunds_queued === 0, "minil dogodek s samo preklicanimi narocili: 200 odpoved (nicesar ni za vrniti)", r.body);
    r = await api("PATCH", `/events/${await dogodek("Minila brez narocil PATCH", -72 * URA)}`, T.lastnik, { status: "cancelled" });
    assert(r.status === 200 && r.body.status === "cancelled", "minil dogodek brez placanih: PATCH cancelled 200 kot doslej", r.body);

    assert(!/Server error|TypeError|ReferenceError|Unhandled/.test(log), "dnevnik brez nepricakovanih napak");
  } catch (e) { fail++; console.log("  ✗ NEPRICAKOVANA NAPAKA:", e); }
  finally {
    srv.kill(); jwksServer.close();
    await pocakaj(200); await pool.end();
    console.log(`\n${ok} OK, ${fail} NAPAK`);
    if (fail) console.log("--- dnevnik streznika (zadnjih 3000 znakov) ---\n" + log.slice(-3000));
    process.exit(fail ? 1 : 0);
  }
})();
