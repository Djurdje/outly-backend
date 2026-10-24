#!/usr/bin/env node
/**
 * Pravo brisanje dogodka, kluba in promo kode v admin panelu (Martin, 24. 10. 2026; invarianta I63, admin_brisanje.js). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_admin_brisanje.js
 * Vzorec kot test_promo_kode.js / test_brisanje_demo_klubov.js: lokalni JWKS (ES256), backend na svojem portu, podatki z neposrednimi INSERT-i.
 *
 *   1  vloge: brez zetona 401; user / business / kupec / zeton agenta (outly_agent_...) 403 na DELETE in na delete-check; nic se ne spremeni
 *   2  razlog: manjka / prekratek / predolg / nevidni znaki -> 400, nic izbrisano
 *   3  dogodek: uspesen izbris z vsemi odvisnimi vrsticami (testna narocila, vstopnice, prenosi, guest lista, gost zetoni, mize, rezervacije, strezba, vracila, spori, ...);
 *      md5 VSEH ostalih tabel je enak kot pred nastankom dogodka; dnevnik admin_dejanja; javni predpomnilnik (I17) takoj ne vrne dogodka; predlog agenta potece; 404 ob ponovitvi
 *   4  dogodek: varovala (pravo placano / pending / refunded / delno vrnjeno / 0 EUR brez Stripa / racun / spor / katerokoli vracilo pravega narocila / preklicano z odprto Stripe sejo) -> 409 s kodo, NIC se ne spremeni;
 *      mrtva seja (> 3 dni, brez PI in paid_at) se izbrise; prijave (reports) ostanejo
 *   5  klub: uspesen izbris (dogodki, mize, paketi, ekipa, vabila, sledilci, promo koda kluba, ogledi; creator_applications.club_id in tuji dogodki -> NULL); uporabniki ostanejo
 *   6  klub: varovala (uradni profil, ime Outly, pravi promet, prizorisce drugega dogodka, tuje narocilo na mizo kluba)
 *   7  promo koda: narocila ostanejo (promo_code_id NULL), finance enake, predogled steje narocila, dnevnik, koda se da znova ustvariti
 *   8  zaklepanje: zaseden zapis (sken) in nakup v teku -> 503 busy brez spremembe; po sprostitvi 409 (nakup) / 200; modul ne uporablja skenPool in ni v agent API-ju
 *   8b nakupna pot: promo koda / dogodek izbrisana med nakupom -> 400 promo_code_invalid / 404 (ne 500)
 *   9  omejevalnik: 21. klic v minuti 429
 */
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6420, JWKS_PORT = 6421;
const BASE = `http://127.0.0.1:${PORT}`;
const KOREN = path.join(__dirname, "..");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-brisanje-admin";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch { return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});
const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
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
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined || method === "GET" ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
const hex = (n) => crypto.createHash("sha256").update("brisanje" + n).digest("hex");

// ---------------------------------------------------------------- podatki
const JSONB = new Set(["spremembe"]);
async function ins(c, tab, o) {
  const k = Object.keys(o);
  const sql = `INSERT INTO ${tab} (${k.join(",")}) VALUES (${k.map((x, i) => "$" + (i + 1) + (JSONB.has(x) ? "::jsonb" : "")).join(",")}) RETURNING *`;
  return (await c.query(sql, k.map((x) => (JSONB.has(x) ? JSON.stringify(o[x]) : o[x])))).rows[0];
}
let stNar = 0;
async function narocilo(c, o) {
  stNar++;
  const kolicina = o.quantity ?? 1, cena = o.unit ?? 1500, status = o.status ?? "paid";
  return ins(c, "orders", {
    public_ref: `OUT-BD${String(stNar).padStart(4, "0")}`, user_id: o.user ?? null, event_id: o.ev, club_id: o.club, quantity: kolicina,
    unit_price_cents: cena, total_cents: cena * kolicina, status, buyer_email: o.email ?? "kupec@example.com",
    paid_at: status === "paid" || status === "refunded" || status === "partially_refunded" ? new Date() : null, stripe_payment_intent_id: o.pi ?? null,
    stripe_checkout_session_id: o.seja ?? null, stripe_account_id: o.acct ?? null, refunded_cents: o.refunded ?? 0,
    table_id: o.tableId ?? null, table_label: o.tableLabel ?? null, table_seats: o.tableSeats ?? null, package_id: o.packageId ?? null, package_name: o.packageName ?? null,
    guest_list_id: o.guestListId ?? null, promo_code_id: o.promo ?? null, cancelled_at: status === "cancelled" ? (o.cancelledAt ?? new Date()) : null, created_at: o.created ?? new Date(),
    ...(o.guest ? { guest_email: "gost@example.com", guest_terms_version: "v1", guest_terms_accepted_at: new Date() } : {}),
  });
}
const STARO = new Date(Date.now() - 5 * 864e5);   // seja potekla pred > 3 dnevi
const testPi = () => "test_" + crypto.randomUUID();
const vstopnica = (c, ord, ev, status = "valid") => ins(c, "tickets", { order_id: ord, event_id: ev, status, ...(status === "used" ? { used_at: new Date() } : {}) });
const dogodek = (c, klub, naslov, pomik, status = "published", extra = {}) => ins(c, "events", {
  club_id: klub, title: naslov, poster_url: "https://example.com/p.jpg", start_at: new Date(Date.now() + pomik * 864e5), status,
  ticket_price_cents: 1500, genres: ["balkan"], vip_enabled: true, ...extra });

// Vsa odvisna vsebina enega dogodka (samo TESTNA in neuspela narocila: to se sme izbrisati).
async function vsebinaDogodka(c, I, ev, klub, { odpovedan = false } = {}) {
  const q = I.kupec, q2 = I.kupec2;
  const miza = await ins(c, "club_tables", { club_id: klub, event_id: ev, label: "E1", x: 1, y: 1, w: 2, h: 2, seats: 6, price_cents: 30000 });   // miza SAMO tega dogodka
  await ins(c, "event_tables", { event_id: ev, table_id: miza.id });
  await ins(c, "table_holds", { event_id: ev, table_id: miza.id, guest_name: "Rezervirano" });
  const nLazni = await narocilo(c, { ev, club: klub, user: q, quantity: 2, pi: testPi(), promo: I.promoKeep });
  const nSandbox = await narocilo(c, { ev, club: klub, user: q, pi: "pi_sandbox" + ev, seja: "cs_test_abc" + ev, acct: "acct_x" });
  const nVip = await narocilo(c, { ev, club: klub, user: q, unit: 30000, pi: testPi(), tableId: miza.id, tableLabel: "E1", tableSeats: 6 });
  const nGost = await narocilo(c, { ev, club: klub, pi: testPi(), guest: true, email: "gost@example.com" });
  const nFailed = await narocilo(c, { ev, club: klub, user: q, status: "failed", seja: "cs_live_dead1" + ev, created: STARO });
  const nCancelled = await narocilo(c, { ev, club: klub, user: q, status: "cancelled", seja: "cs_live_dead2" + ev, created: STARO, cancelledAt: STARO });
  const nVrnjeno = await narocilo(c, { ev, club: klub, user: q, status: "refunded", pi: testPi(), refunded: 1500 });
  const tLazni = [await vstopnica(c, nLazni.id, ev), await vstopnica(c, nLazni.id, ev, "used")];
  const tSandbox = await vstopnica(c, nSandbox.id, ev);
  const tVip = await vstopnica(c, nVip.id, ev);
  const tGost = await ins(c, "tickets", { order_id: nGost.id, event_id: ev, holder_is_guest: true, holder_guest_email: "gost@example.com" });
  await ins(c, "ticket_transfers", { ticket_id: tSandbox.id, from_user_id: q, to_user_id: q2, to_email: "kupec2@example.com", old_serial: crypto.randomUUID(), new_serial: crypto.randomUUID() });
  await ins(c, "gost_zetoni", { token_hash: hex("gz" + nGost.id), order_id: nGost.id });
  await ins(c, "gost_zetoni_vstopnic", { token_hash: hex("gzv" + tGost.id), ticket_id: tGost.id });
  await ins(c, "table_service", { event_id: ev, order_id: nVip.id, club_id: klub, table_label: "E1", table_seats: 6, scanned_at: new Date() });
  const gl = await ins(c, "guest_lists", { event_id: ev, host_user_id: q, spots: 5, created_by: I.admin });
  const nGl = await narocilo(c, { ev, club: klub, user: q, unit: 0, guestListId: gl.id });
  const tGl = await vstopnica(c, nGl.id, ev);
  await ins(c, "guest_list_members", { guest_list_id: gl.id, user_id: q, ticket_id: tGl.id });
  await ins(c, "vracila", { order_id: nVrnjeno.id, event_id: ev, razlog: "event_cancelled", stanje: "opravljeno", znesek_cents: 1500, brez_stripa: true, stripe_vracilo_id: "re_test_oznaka", provizija_vracilo_id: "fr_test_oznaka" });
  await ins(c, "spori", { id: "dp_" + ev, order_id: nSandbox.id, stanje: "odprt" });
  await ins(c, "vracila_iz_stripa", { vracilo_id: "re_" + ev, charge_id: "ch_" + ev, order_id: nSandbox.id, znesek_cents: 100, skupaj_vrnjeno_cents: 100 });
  await ins(c, "view_counts", { club_id: klub, event_id: ev, day: "2026-10-01", count: 3 });
  await ins(c, "event_favorites", { user_id: q, event_id: ev });
  await ins(c, "event_interest", { user_id: q, event_id: ev });
  await ins(c, "club_event_notifications", { user_id: q, event_id: ev });
  await ins(c, "promo_code_events", { promo_code_id: I.promoKeep, event_id: ev });
  await ins(c, "reports", { reporter_id: q, target_type: "event", target_id: ev, reason: "spam" });
  const predlog = await ins(c, "predlogi_dejanj", { agent_zeton_id: I.zetonAgenta, dejanje: "event.ustavi_prodajo", cilj_tip: "event", cilj_id: ev, spremembe: {}, razlog: "test" });
  return { predlog: predlog.id, vrstic: { orders: 8, tickets: 6 } };
}

// md5 vrstic vseh tabel (razen tistih, ki se pri brisanju namenoma spremenijo).
const IZVZETE = new Set(["schema_migrations", "admin_dejanja", "predlogi_dejanj", "omejitve", "stripe_events"]);
async function posnetek(c, izvzete = []) {
  const tabele = (await c.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1")).rows.map((x) => x.table_name);
  const izid = {};
  for (const t of tabele) {
    if (IZVZETE.has(t) || izvzete.includes(t)) continue;
    const r = await c.query(`SELECT COUNT(*)::int AS n, md5(COALESCE(string_agg(x.j, '|' ORDER BY x.j), '')) AS h FROM (SELECT to_jsonb(t)::text AS j FROM "${t}" t) x`);
    izid[t] = r.rows[0];
  }
  return izid;
}
const razlike = (a, b) => Object.keys(a).filter((t) => a[t].n !== b[t].n || a[t].h !== b[t].h);

(async () => {
  const pool = new Pool({ connectionString: DB });
  const tabeleVse = (await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name <> 'schema_migrations'")).rows.map((x) => `"${x.table_name}"`);
  await pool.query(`TRUNCATE ${tabeleVse.join(", ")} RESTART IDENTITY CASCADE`);
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { cwd: KOREN, env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    TEST_PLACILA: "", ADMIN_BRISANJE_ZAKLEP_MS: "500", VRACILA_TICK_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }

  const c = await pool.connect();
  const T = { admin: zeton("admin@outly.si", uuid(1)), lastnik: zeton("lastnik@outly.si", uuid(2)), kupec: zeton("kupec@outly.si", uuid(3)), navaden: zeton("navaden@outly.si", uuid(4)) };
  const AGENT = "outly_agent_" + "A".repeat(43);
  try {
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    const uid = async (e) => (await pool.query("SELECT id FROM users WHERE email=$1", [e])).rows[0].id;
    const I = { admin: await uid("admin@outly.si"), kupec: await uid("kupec@outly.si"), lastnik: await uid("lastnik@outly.si") };
    const mkUser = async (email, vloga = "user") => (await ins(pool, "users", { email, username: email.split("@")[0], role: vloga, email_verified: true, supabase_uid: crypto.randomUUID() })).id;
    I.kupec2 = await mkUser("kupec2@example.com");
    I.clan = await mkUser("clan@example.com");
    I.lastnikC2 = await mkUser("lastnik.c2@example.com", "business");
    I.lastnikC3 = await mkUser("lastnik.c3@example.com", "business");
    I.lastnikOff = await mkUser("lastnik.off@example.com", "business");
    I.lastnikOutly = await mkUser("lastnik.outly@example.com", "business");
    I.lastnikC4 = await mkUser("lastnik.c4@example.com", "business");
    I.prosilec = await mkUser("prosilec@example.com");
    I.zetonAgenta = (await ins(pool, "agent_zetoni", { ime: "test", zeton_sha256: hex("zeton"), obseg: ["beri", "predlagaj"], velja_do: new Date(Date.now() + 864e5) })).id;

    // ---- BAZA A: kar mora ostati bit-za-bitom (klub D z dogodkom EK s PRAVIMI placanimi narocili, racunom, sporom, uradni klub ...)
    const D = (await ins(pool, "clubs", { owner_user_id: I.lastnik, name: "Klub D", city: "Ljubljana" })).id;
    const EK = (await dogodek(pool, D, "Pravi dogodek", 10)).id;
    I.promoKeep = (await ins(pool, "promo_codes", { code: "KEEP1", label: "ostane", club_id: D, created_by: I.admin })).id;
    await ins(pool, "promo_code_events", { promo_code_id: I.promoKeep, event_id: EK });
    const r1 = await narocilo(pool, { ev: EK, club: D, user: I.kupec, pi: "pi_live1", seja: "cs_live_1", acct: "acct_d" });
    await vstopnica(pool, r1.id, EK);
    await ins(pool, "racuni", { order_id: r1.id, vrsta: "racun", znesek_cents: 1500 });
    await ins(pool, "spori", { id: "dp_keep", order_id: r1.id, stanje: "odprt" });
    await ins(pool, "view_counts", { club_id: D, event_id: EK, day: "2026-10-01", count: 9 });
    const OFF = (await ins(pool, "clubs", { owner_user_id: I.lastnikOff, name: "Uradni", city: "Ljubljana", is_official: true, is_organizer: true })).id;
    const OUTLY = (await ins(pool, "clubs", { owner_user_id: I.lastnikOutly, name: " outly ", city: "Ljubljana" })).id;
    const pA = await posnetek(pool);
    const omejitveCisti = () => pool.query("TRUNCATE omejitve");

    // ============================================================
    console.log("\n# 1. Vloge");
    const E1 = (await dogodek(pool, D, "Za brisanje 1", 20)).id;
    const C1 = (await ins(pool, "clubs", { owner_user_id: I.lastnikC2, name: "Za brisanje klub 1", city: "Maribor" })).id;
    const PK = (await ins(pool, "promo_codes", { code: "ROLE1", label: "vloge", club_id: D, created_by: I.admin })).id;
    for (const [m, p] of [["DELETE", `/admin/api/events/${E1}`], ["GET", `/admin/api/events/${E1}/delete-check`], ["DELETE", `/admin/api/clubs/${C1}`], ["GET", `/admin/api/clubs/${C1}/delete-check`],
      ["DELETE", `/admin/api/promo-codes/${PK}`], ["GET", `/admin/api/promo-codes/${PK}/delete-check`]]) {
      let r = await api(m, p, null, { reason: "test brisanja" });
      assert(r.status === 401, `${m} ${p} brez zetona -> 401`, r.status);
      for (const k of ["navaden", "lastnik", "kupec"]) {
        r = await api(m, p, T[k], { reason: "test brisanja" });
        assert(r.status === 403, `${m} ${p} (${k}) -> 403`, r.status);
      }
      r = await api(m, p, AGENT, { reason: "test brisanja" });
      assert(r.status === 403, `${m} ${p} (zeton agenta) -> 403`, r.status);
    }
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE id=$1", [E1])).rows[0].n === 1
      && (await pool.query("SELECT COUNT(*)::int AS n FROM clubs WHERE id=$1", [C1])).rows[0].n === 1
      && (await pool.query("SELECT COUNT(*)::int AS n FROM promo_codes WHERE id=$1", [PK])).rows[0].n === 1, "403/401 niso nicesar izbrisali");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM admin_dejanja")).rows[0].n === 0, "403/401 niso pustili vrstice v dnevniku");

    console.log("\n# 2. Razlog je obvezen");
    await omejitveCisti();
    const slabRazlog = async (opis, telo) => {
      for (const p of [`/admin/api/events/${E1}`, `/admin/api/clubs/${C1}`, `/admin/api/promo-codes/${PK}`]) {
        const r = await api("DELETE", p, T.admin, telo);
        assert(r.status === 400 && /^reason_/.test(r.body.error), `DELETE ${p.split("/")[3]} ${opis} -> 400 reason_*`, [r.status, r.body]);
      }
    };
    await slabRazlog("brez telesa", undefined);
    await slabRazlog("brez razloga", {});
    await slabRazlog("razlog »ab«", { reason: "ab" });
    await slabRazlog("razlog ni niz", { reason: 12345 });
    await slabRazlog("razlog 501 znakov", { reason: "x".repeat(501) });
    await slabRazlog("razlog z nevidnim znakom", { reason: "dober‮razlog" });
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE id=$1", [E1])).rows[0].n === 1
      && (await pool.query("SELECT COUNT(*)::int AS n FROM clubs WHERE id=$1", [C1])).rows[0].n === 1
      && (await pool.query("SELECT COUNT(*)::int AS n FROM promo_codes WHERE id=$1", [PK])).rows[0].n === 1, "400 niso nicesar izbrisali");
    await omejitveCisti();
    let r = await api("DELETE", "/admin/api/events/abc", T.admin, { reason: "test brisanja" });
    assert(r.status === 400 && r.body.error === "invalid_id", "neveljaven id dogodka -> 400", r);
    r = await api("DELETE", "/admin/api/events/999999", T.admin, { reason: "test brisanja" });
    assert(r.status === 404 && r.body.error === "not_found", "neobstojec dogodek -> 404", r);
    r = await api("DELETE", "/admin/api/clubs/999999", T.admin, { reason: "test brisanja" });
    assert(r.status === 404, "neobstojec klub -> 404", r.status);
    r = await api("DELETE", "/admin/api/promo-codes/999999", T.admin, { reason: "test brisanja" });
    assert(r.status === 404, "neobstojec koda -> 404", r.status);
    await pool.query("DELETE FROM events WHERE id=$1", [E1]); await pool.query("DELETE FROM clubs WHERE id=$1", [C1]); await pool.query("DELETE FROM promo_codes WHERE id=$1", [PK]);

    // ============================================================
    console.log("\n# 3. Dogodek: uspesen izbris z vsemi odvisnimi vrsticami");
    await omejitveCisti();
    const ED = (await dogodek(pool, D, "Dogodek za brisanje", 12)).id;
    const ED2 = (await dogodek(pool, D, "Odpovedan za brisanje", 5, "cancelled")).id;   // sprozilec events_odpoved zapise odpovedi_dogodkov
    const f1 = await vsebinaDogodka(pool, I, ED, D);
    const f2 = await vsebinaDogodka(pool, I, ED2, D);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM odpovedi_dogodkov WHERE event_id=$1", [ED2])).rows[0].n === 1, "odpovedan dogodek ima vrstico odpovedi_dogodkov (izhodisce)");
    // javni predpomnilnik (I17): ogrej /events/:id in /events, nato izbrisi -> takoj 404 in dogodka ni na seznamu
    let pr = await api("GET", `/events/${ED}`); assert(pr.status === 200, "GET /events/:id pred brisanjem 200 (ogreje predpomnilnik)");
    pr = await api("GET", "/events"); assert(pr.status === 200 && JSON.stringify(pr.body).includes("Dogodek za brisanje"), "GET /events vsebuje dogodek pred brisanjem");
    r = await api("GET", `/admin/api/events/${ED}/delete-check`, T.admin);
    assert(r.status === 200 && r.body.can_delete === true && r.body.blockers.length === 0 && r.body.event.id === ED, "delete-check: can_delete", r.body);
    assert(r.body.will_delete.orders === 8 && r.body.will_delete.real_failed_orders === 2 && r.body.will_delete.tickets === 6 && r.body.will_delete.guest_lists === 1, "delete-check: stevila (8 narocil, od tega 2 prava preklicana/neuspela z mrtvo sejo prikazana loceno, 6 vstopnic, 1 guest lista)", r.body.will_delete);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [ED])).rows[0].n === 8, "delete-check nic ne spremeni");
    r = await api("GET", `/admin/api/events/${ED}/delete-check?lite=1`, T.admin);
    assert(r.status === 200 && r.body.can_delete === true && r.body.lite === true && r.body.will_delete === undefined, "delete-check?lite=1: samo blokade, brez kaskade (P2)", r.body);
    r = await api("DELETE", `/admin/api/events/${ED2}`, T.admin, { reason: "odpovedan testni dogodek" });
    assert(r.status === 200 && r.body.deleted === true && r.body.event_id === ED2, "DELETE odpovedanega dogodka -> 200", r);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM odpovedi_dogodkov WHERE event_id=$1", [ED2])).rows[0].n === 0, "odpovedi_dogodkov izginil s kaskado");
    r = await api("DELETE", `/admin/api/events/${ED}`, T.admin, { reason: "  testni dogodek, ni vec potreben  " });
    assert(r.status === 200 && r.body.deleted === true && r.body.counts.orders === 8 && r.body.counts.tickets === 6 && r.body.counts.guest_lists === 1, "DELETE dogodka -> 200 s stevili", r);
    assert(r.body.counts.event_tables === 1 && r.body.counts.table_holds === 1 && r.body.counts.club_tables === 1 && r.body.counts.table_service === 1 && r.body.counts.vracila === 1 && r.body.counts.spori === 1
      && r.body.counts.vracila_iz_stripa === 1 && r.body.counts.gost_zetoni === 1 && r.body.counts.ticket_transfers === 1 && r.body.counts.guest_list_members === 1 && r.body.counts.event_favorites === 1
      && r.body.counts.promo_code_events === 1, "stevila po tabelah v odgovoru", r.body.counts);
    pr = await api("GET", `/events/${ED}`); assert(pr.status === 404, "javni predpomnilnik: GET /events/:id takoj 404", pr.status);
    pr = await api("GET", "/events"); assert(pr.status === 200 && !JSON.stringify(pr.body).includes("Dogodek za brisanje"), "javni predpomnilnik: GET /events brez izbrisanega dogodka");
    r = await api("GET", `/admin/api/events/${ED}`, T.admin); assert(r.status === 404, "GET /admin/api/events/:id -> 404", r.status);
    r = await api("DELETE", `/admin/api/events/${ED}`, T.admin, { reason: "ponovitev" }); assert(r.status === 404, "ponovni DELETE -> 404", r.status);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM reports WHERE target_type='event' AND target_id = ANY($1::int[])", [[ED, ED2]])).rows[0].n === 2, "prijave (reports) izbrisanih dogodkov OSTANEJO kot dokaz (M1)");
    await pool.query("DELETE FROM reports WHERE target_type='event' AND target_id = ANY($1::int[])", [[ED, ED2]]);   // za md5 primerjavo
    const pB = await posnetek(pool);
    assert(razlike(pA, pB).length === 0, "md5 VSEH ostalih tabel je enak kot pred nastankom dogodka", razlike(pA, pB));
    const dnev = (await pool.query("SELECT * FROM admin_dejanja WHERE dejanje='event.delete_hard' ORDER BY id")).rows;
    assert(dnev.length === 2 && dnev[1].cilj_tip === "event" && dnev[1].cilj_id === String(ED) && dnev[1].admin_user_id === I.admin && dnev[1].razlog === "testni dogodek, ni vec potreben"
      && dnev[1].prej.title === "Dogodek za brisanje" && dnev[1].prej.club_id === D && dnev[1].potem.deleted.orders === 8 && dnev[1].potem.deleted.tickets === 6, "admin_dejanja: event.delete_hard (cilj, admin, razlog, prej, potem)", dnev[1]);
    assert(!/@/.test(JSON.stringify([dnev[0].prej, dnev[0].potem, dnev[1].prej, dnev[1].potem])), "dnevnik brez e-naslovov");
    const pl = (await pool.query("SELECT stanje, odloceno_at FROM predlogi_dejanj WHERE id=$1", [f1.predlog])).rows[0];
    assert(pl.stanje === "potekel" && pl.odloceno_at !== null, "odprt predlog agenta za izbrisani dogodek je potekel", pl);

    // ============================================================
    console.log("\n# 4. Dogodek: varovala (409, nic se ne spremeni)");
    const varovalo = async (opis, koda, pripravi) => {
      await omejitveCisti();
      const ev = (await dogodek(pool, D, "Varovan: " + opis, 30)).id;
      await pripravi(ev);
      const prej = (await pool.query("SELECT (SELECT COUNT(*)::int FROM orders WHERE event_id=$1) AS o, (SELECT COUNT(*)::int FROM tickets WHERE event_id=$1) AS t", [ev])).rows[0];
      const chk = await api("GET", `/admin/api/events/${ev}/delete-check`, T.admin);
      assert(chk.status === 200 && chk.body.can_delete === false && chk.body.blockers.some((b) => b.code === koda), `${opis}: delete-check can_delete=false (${koda})`, chk.body);
      const x = await api("DELETE", `/admin/api/events/${ev}`, T.admin, { reason: "poskus brisanja" });
      assert(x.status === 409 && (x.body.error === koda || (x.body.blockers || []).some((b) => b.code === koda)) && Array.isArray(x.body.blockers) && typeof x.body.message === "string", `${opis}: DELETE -> 409 ${koda}`, [x.status, x.body]);
      const po = (await pool.query("SELECT (SELECT COUNT(*)::int FROM events WHERE id=$1) AS e, (SELECT COUNT(*)::int FROM orders WHERE event_id=$1) AS o, (SELECT COUNT(*)::int FROM tickets WHERE event_id=$1) AS t", [ev])).rows[0];
      assert(po.e === 1 && po.o === prej.o && po.t === prej.t, `${opis}: dogodek, narocila in vstopnice so cele`, po);
      return ev;
    };
    await varovalo("pravo placano narocilo", "has_real_orders", async (ev) => { const n = await narocilo(pool, { ev, club: D, user: I.kupec, pi: "pi_live_a", seja: "cs_live_a" }); await vstopnica(pool, n.id, ev); });
    await varovalo("pravo narocilo v teku (pending)", "has_real_orders", async (ev) => { await narocilo(pool, { ev, club: D, user: I.kupec, status: "pending", seja: "cs_live_p" }); });
    await varovalo("pravo v celoti vrnjeno narocilo", "has_real_orders", async (ev) => { await narocilo(pool, { ev, club: D, user: I.kupec, status: "refunded", pi: "pi_live_r", seja: "cs_live_r", refunded: 1500 }); });
    await varovalo("pravo delno vrnjeno narocilo", "has_real_orders", async (ev) => { await narocilo(pool, { ev, club: D, user: I.kupec, status: "partially_refunded", pi: "pi_live_d", seja: "cs_live_d", refunded: 500 }); });
    await varovalo("pravo 0 EUR narocilo brez Stripa (I39: pravi promet)", "has_real_orders", async (ev) => { await narocilo(pool, { ev, club: D, user: I.kupec, unit: 0 }); });
    await varovalo("racun za testno narocilo", "has_invoices", async (ev) => { const n = await narocilo(pool, { ev, club: D, user: I.kupec, pi: testPi() }); await ins(pool, "racuni", { order_id: n.id, vrsta: "racun", znesek_cents: 1500 }); });
    await varovalo("racun za pravo cancelled narocilo", "has_invoices", async (ev) => { const n = await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled", seja: "cs_live_c", created: STARO, cancelledAt: STARO }); await ins(pool, "racuni", { order_id: n.id, vrsta: "racun", znesek_cents: 1500 }); });
    await varovalo("spor za pravo failed narocilo", "has_disputes", async (ev) => { const n = await narocilo(pool, { ev, club: D, user: I.kupec, status: "failed", seja: "cs_live_f", created: STARO }); await ins(pool, "spori", { id: "dp_g" + ev, order_id: n.id, stanje: "odprt" }); });
    await varovalo("Stripovo vracilo (vracila_iz_stripa) za pravo cancelled narocilo", "has_refunds", async (ev) => {
      const n = await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled", seja: "cs_live_g", created: STARO, cancelledAt: STARO });
      await ins(pool, "vracila_iz_stripa", { vracilo_id: "re_g" + ev, charge_id: "ch_g" + ev, order_id: n.id, znesek_cents: 100, skupaj_vrnjeno_cents: 100 }); });
    await varovalo("vracilo z oznako Stripa za pravo cancelled narocilo", "has_refunds", async (ev) => {
      const n = await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled", seja: "cs_live_h", created: STARO, cancelledAt: STARO });
      await ins(pool, "vracila", { order_id: n.id, event_id: ev, razlog: "inactive_order", stanje: "opravljeno", znesek_cents: 100, stripe_vracilo_id: "re_h" + ev }); });
    // B2: VSAKA vrstica vracila za pravo narocilo blokira (tudi caka/ni_uspelo brez Stripovega ID-ja: kupec utegne se cakati denar); PI zraven doda se checkout_may_complete
    await varovalo("pravo cancelled narocilo s PI + vracilo v stanju caka brez Stripovega ID-ja", "has_refunds", async (ev) => {
      const n = await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled", pi: "pi_live_v" + ev, seja: "cs_live_v" + ev });
      await ins(pool, "vracila", { order_id: n.id, event_id: ev, razlog: "inactive_order", stanje: "caka", znesek_cents: 1500 }); });
    await varovalo("pravo mrtvo cancelled narocilo + vracilo ni_uspelo (brez Stripovega ID-ja)", "has_refunds", async (ev) => {
      const n = await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled", seja: "cs_live_w" + ev, created: STARO, cancelledAt: STARO });
      await ins(pool, "vracila", { order_id: n.id, event_id: ev, razlog: "inactive_order", stanje: "ni_uspelo", znesek_cents: 1500 }); });
    // B1: preklicano/neuspelo pravo narocilo, ki ga kupec se utegne placati (Stripe seja, PI ali paid_at), blokira
    await varovalo("cancelled z odprto Stripe sejo", "checkout_may_complete", async (ev) => { await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled", seja: "cs_live_o" + ev }); });
    await varovalo("cancelled, seja potekla pred 2 dnevi (znotraj 3 dni webhookov)", "checkout_may_complete", async (ev) => {
      const d2 = new Date(Date.now() - 2 * 864e5); await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled", seja: "cs_live_p" + ev, created: d2, cancelledAt: d2 }); });
    await varovalo("failed s PaymentIntentom", "checkout_may_complete", async (ev) => { await narocilo(pool, { ev, club: D, user: I.kupec, status: "failed", pi: "pi_live_q" + ev, seja: "cs_live_q" + ev, created: STARO }); });
    await varovalo("cancelled, ki je bil ze placan (paid_at), seja stara", "checkout_may_complete", async (ev) => {
      const n = await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled", seja: "cs_live_r" + ev, created: STARO, cancelledAt: STARO }); await pool.query("UPDATE orders SET paid_at = NOW() WHERE id=$1", [n.id]); });
    // dovoljeno: pravo failed/cancelled narocilo z dokazano mrtvo sejo (brez PI in paid_at, starejse od 3 dni) ali brez seje/PI/paid_at (nakup se ni stekel do Stripa)
    {
      await omejitveCisti();
      const ev = (await dogodek(pool, D, "Samo mrtva narocila", 31)).id;
      await narocilo(pool, { ev, club: D, user: I.kupec, status: "failed", seja: "cs_live_x1" + ev, created: STARO });
      await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled", seja: "cs_live_x2" + ev, created: STARO, cancelledAt: STARO });
      await narocilo(pool, { ev, club: D, user: I.kupec, status: "cancelled" });
      const chk = await api("GET", `/admin/api/events/${ev}/delete-check`, T.admin);
      assert(chk.status === 200 && chk.body.can_delete === true && chk.body.will_delete.orders === 3 && chk.body.will_delete.real_failed_orders === 3, "delete-check: 3 prava preklicana/neuspela naročila z mrtvo sejo so prikazana loceno (P4)", chk.body);
      const x = await api("DELETE", `/admin/api/events/${ev}`, T.admin, { reason: "samo mrtva narocila" });
      assert(x.status === 200 && x.body.counts.orders === 3 && x.body.real_failed_orders === 3, "pravi failed/cancelled z mrtvo sejo ali brez seje (brez racuna/spora/vracil) se izbrisejo", x);
      const dn = (await pool.query("SELECT potem FROM admin_dejanja WHERE dejanje='event.delete_hard' AND cilj_id=$1", [String(ev)])).rows[0];
      assert(dn && dn.potem.real_failed_orders === 3, "dnevnik: real_failed_orders", dn);
    }
    // pravi promet drugega dogodka ostane
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE id=$1", [r1.id])).rows[0].n === 1, "pravo narocilo drugega dogodka je cielo");

    // ============================================================
    console.log("\n# 5. Klub: uspesen izbris");
    await omejitveCisti();
    const pA2 = await posnetek(pool);   // nova osnova: vkljucuje ostanke varoval iz razdelka 4 (dogodki s pravimi narocili ostanejo)
    const C2 = (await ins(pool, "clubs", { owner_user_id: I.lastnikC2, name: "Klub za brisanje", city: "Maribor", genres: ["techno"] })).id;
    await ins(pool, "club_members", { club_id: C2, user_id: I.clan, role: "doorman" });
    await ins(pool, "club_invites", { club_id: C2, user_id: I.kupec2, role: "manager" });
    await ins(pool, "club_follows", { club_id: C2, user_id: I.kupec });
    const cTabela = await ins(pool, "club_tables", { club_id: C2, label: "K1", x: 1, y: 1, w: 2, h: 2, seats: 6, price_cents: 20000 });
    const cPaket = await ins(pool, "bottle_packages", { club_id: C2, name: "Jameson", description: "x" });
    const promoC2 = await ins(pool, "promo_codes", { code: "KLUBC2", label: "klub", club_id: C2, created_by: I.admin });
    const EC1 = (await dogodek(pool, C2, "C2 dogodek 1", 8)).id;
    const EC2 = (await dogodek(pool, C2, "C2 dogodek 2 (odpovedan)", 4, "cancelled")).id;
    await ins(pool, "promo_code_events", { promo_code_id: promoC2.id, event_id: EC1 });
    await vsebinaDogodka(pool, I, EC1, C2);
    await vsebinaDogodka(pool, I, EC2, C2);
    await ins(pool, "event_tables", { event_id: EC1, table_id: cTabela.id });
    await narocilo(pool, { ev: EC1, club: C2, user: I.kupec, pi: testPi(), tableId: cTabela.id, tableLabel: "K1", tableSeats: 6, packageId: cPaket.id, packageName: "Jameson", promo: promoC2.id, unit: 20000 });
    await ins(pool, "view_counts", { club_id: C2, day: "2026-10-02", count: 5 });
    await ins(pool, "reports", { reporter_id: I.kupec, target_type: "club", target_id: C2, reason: "spam" });
    await ins(pool, "reports", { reporter_id: I.kupec, target_type: "media", target_id: C2, reason: "spam" });
    const predlogKluba = await ins(pool, "predlogi_dejanj", { agent_zeton_id: I.zetonAgenta, dejanje: "event.ustavi_prodajo", cilj_tip: "club", cilj_id: C2, spremembe: {}, razlog: "test" });
    const prosnja = await ins(pool, "creator_applications", { user_id: I.prosilec, business_name: "Klub za brisanje", contact_name: "Janez", email: "prosilec@example.com", status: "approved", decided_at: new Date(), club_id: C2 });
    // dogodek DRUGEGA kluba, odpovedan, z C2 kot prizoriscem: ostane, prizorisce postane NULL
    const EV = (await dogodek(pool, D, "Gostovanje pri C2", 40, "cancelled", { venue_club_id: C2, vip_layout_from_club_id: C2 })).id;
    r = await api("GET", `/admin/api/clubs/${C2}/delete-check`, T.admin);
    assert(r.status === 200 && r.body.can_delete === true && r.body.events_total === 2 && r.body.will_delete.events === 2 && r.body.will_delete.orders === 17 && r.body.will_delete.promo_codes === 1
      && r.body.will_delete.club_members === 1 && r.body.will_delete.bottle_packages === 1, "delete-check kluba: 2 dogodka, 17 narocil, promo koda, ekipa, paket", r.body);
    r = await api("DELETE", `/admin/api/clubs/${C2}`, T.admin, { reason: "testni klub ni vec potreben" });
    assert(r.status === 200 && r.body.deleted === true && r.body.club_id === C2 && r.body.counts.events === 2 && r.body.counts.clubs === 1 && r.body.counts.orders === 17, "DELETE kluba -> 200 s stevili", r);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM clubs WHERE id=$1", [C2])).rows[0].n === 0, "klub izbrisan");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE club_id=$1", [C2])).rows[0].n === 0, "dogodki kluba izbrisani");
    const ev2 = (await pool.query("SELECT venue_club_id, vip_layout_from_club_id FROM events WHERE id=$1", [EV])).rows[0];
    assert(ev2 && ev2.venue_club_id === null && ev2.vip_layout_from_club_id === null, "tuj dogodek ostane, prizorisce in tloris -> NULL", ev2);
    const pr2 = (await pool.query("SELECT club_id FROM creator_applications WHERE id=$1", [prosnja.id])).rows[0];
    assert(pr2 && pr2.club_id === null, "creator_applications ostane, club_id -> NULL", pr2);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE id = ANY($1::int[])", [[I.lastnikC2, I.clan, I.kupec2, I.kupec, I.prosilec]])).rows[0].n === 5, "uporabniki (lastnik, clan, ...) ostanejo");
    assert((await pool.query("SELECT stanje FROM predlogi_dejanj WHERE id=$1", [predlogKluba.id])).rows[0].stanje === "potekel", "odprt predlog agenta za klub je potekel");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM reports WHERE target_id=$1 AND target_type IN ('club','media')", [C2])).rows[0].n === 2, "prijave kluba in slik OSTANEJO kot dokaz (M1)");
    await pool.query("DELETE FROM reports WHERE target_id=$1 AND target_type IN ('club','media')", [C2]);   // za md5 primerjavo
    await pool.query("DELETE FROM reports WHERE target_type='event' AND target_id = ANY($1::int[])", [[EC1, EC2]]);
    const dk = (await pool.query("SELECT * FROM admin_dejanja WHERE dejanje='club.delete'")).rows;
    assert(dk.length === 1 && dk[0].cilj_tip === "club" && dk[0].cilj_id === String(C2) && dk[0].admin_user_id === I.admin && dk[0].razlog === "testni klub ni vec potreben" && dk[0].prej.name === "Klub za brisanje"
      && dk[0].prej.events_total === 2 && dk[0].potem.deleted.clubs === 1 && dk[0].potem.deleted.promo_codes === 1, "admin_dejanja: club.delete", dk[0]);
    assert(!/@/.test(JSON.stringify([dk[0].prej, dk[0].potem])), "dnevnik kluba brez e-naslovov");
    await pool.query("DELETE FROM events WHERE id=$1", [EV]); await pool.query("DELETE FROM creator_applications WHERE id=$1", [prosnja.id]);
    const pC = await posnetek(pool);
    assert(razlike(pA2, pC).length === 0, "md5 VSEH tabel je po izbrisu kluba enak kot pred njegovim nastankom", razlike(pA2, pC));

    // ============================================================
    console.log("\n# 6. Klub: varovala");
    await omejitveCisti();
    const klubVarovalo = async (opis, koda, id, pripravi) => {
      if (pripravi) await pripravi();
      const chk = await api("GET", `/admin/api/clubs/${id}/delete-check`, T.admin);
      assert(chk.status === 200 && chk.body.can_delete === false && chk.body.blockers.some((b) => b.code === koda), `${opis}: delete-check can_delete=false (${koda})`, chk.body);
      const x = await api("DELETE", `/admin/api/clubs/${id}`, T.admin, { reason: "poskus brisanja kluba" });
      assert(x.status === 409 && x.body.error === koda, `${opis}: DELETE -> 409 ${koda}`, [x.status, x.body]);
      assert((await pool.query("SELECT COUNT(*)::int AS n FROM clubs WHERE id=$1", [id])).rows[0].n === 1, `${opis}: klub je ostal`);
    };
    await klubVarovalo("uradni profil (is_official)", "official_club", OFF);
    await klubVarovalo("klub z imenom Outly", "official_club", OUTLY);
    const C3 = (await ins(pool, "clubs", { owner_user_id: I.lastnikC3, name: "Klub s prometom", city: "Celje" })).id;
    const EC3 = (await dogodek(pool, C3, "C3 dogodek", 9)).id;
    await klubVarovalo("klub s pravim placanim narocilom", "has_real_orders", C3, async () => { await narocilo(pool, { ev: EC3, club: C3, user: I.kupec, pi: "pi_live_c3", seja: "cs_live_c3" }); });
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE id=$1", [EC3])).rows[0].n === 1, "dogodki kluba s prometom ostanejo");
    const C4 = (await ins(pool, "clubs", { owner_user_id: I.lastnikC4, name: "Prizorisce", city: "Koper" })).id;
    const gost = await dogodek(pool, D, "Gostuje pri C4", 25, "published", { venue_club_id: C4 });
    await klubVarovalo("neodpovedan dogodek drugega kluba ima klub za prizorisce", "venue_in_use", C4);
    await pool.query("UPDATE events SET status='cancelled' WHERE id=$1", [gost.id]);
    const mizaC4 = await ins(pool, "club_tables", { club_id: C4, label: "P1", x: 1, y: 1, w: 2, h: 2, seats: 4, price_cents: 10000 });
    const tuj = await narocilo(pool, { ev: EK, club: D, user: I.kupec, status: "cancelled", seja: "cs_live_tuj", tableId: mizaC4.id, tableLabel: "P1", tableSeats: 4, unit: 10000 });
    await klubVarovalo("narocilo drugega dogodka kaze na mizo kluba", "foreign_references", C4);
    await pool.query("DELETE FROM orders WHERE id=$1", [tuj.id]);
    r = await api("DELETE", `/admin/api/clubs/${C4}`, T.admin, { reason: "prizorisce ni vec v rabi" });
    assert(r.status === 200 && r.body.deleted === true, "ko je gostujoci dogodek odpovedan in narocila ni vec, klub se izbrise", r);
    assert((await pool.query("SELECT venue_club_id FROM events WHERE id=$1", [gost.id])).rows[0].venue_club_id === null, "odpovedan gostujoci dogodek ostane brez prizorisca");
    await pool.query("DELETE FROM events WHERE id=$1", [gost.id]);
    await pool.query("DELETE FROM tickets WHERE order_id IN (SELECT id FROM orders WHERE club_id=$1)", [C3]);
    await pool.query("DELETE FROM orders WHERE club_id=$1", [C3]);
    await pool.query("DELETE FROM events WHERE club_id=$1", [C3]);
    await pool.query("DELETE FROM clubs WHERE id=$1", [C3]);

    // ============================================================
    console.log("\n# 7. Promo koda");
    await omejitveCisti();
    const P1 = (await ins(pool, "promo_codes", { code: "BRISI1", label: "za brisanje", club_id: D, created_by: I.admin })).id;
    await ins(pool, "promo_code_events", { promo_code_id: P1, event_id: EK });
    const np1 = await narocilo(pool, { ev: EK, club: D, user: I.kupec, quantity: 2, pi: "pi_live_p1", seja: "cs_live_p1", promo: P1 });
    await vstopnica(pool, np1.id, EK); await vstopnica(pool, np1.id, EK);
    const np2 = await narocilo(pool, { ev: EK, club: D, user: I.kupec, pi: testPi(), promo: P1 });
    const np3 = await narocilo(pool, { ev: EK, club: D, user: I.kupec, pi: "pi_live_p3", seja: "cs_live_p3", promo: I.promoKeep });
    const fin0 = await api("GET", "/admin/api/finance?from=2020-01-01&to=2030-01-01", T.admin);
    const pS1 = await posnetek(pool);
    const ordersBrezPromo = async () => (await pool.query("SELECT md5(string_agg((to_jsonb(o) - 'promo_code_id')::text, '|' ORDER BY o.id)) AS h, COUNT(*)::int AS n FROM orders o")).rows[0];
    const o1 = await ordersBrezPromo();
    r = await api("GET", `/admin/api/promo-codes/${P1}/delete-check`, T.admin);
    assert(r.status === 200 && r.body.can_delete === true && r.body.orders_using_code === 2 && r.body.promo_code.code === "BRISI1", "delete-check: koda uporabljena pri 2 narocilih", r.body);
    r = await api("DELETE", `/admin/api/promo-codes/${P1}`, T.admin, { reason: "koda ni vec v rabi" });
    assert(r.status === 200 && r.body.deleted === true && r.body.orders_detached === 2 && r.body.counts.promo_codes === 1, "DELETE promo kode -> 200, 2 narocili odvezani", r);
    const o2 = await ordersBrezPromo();
    assert(o1.h === o2.h && o1.n === o2.n && o2.n > 0, "narocila ostanejo (vse razen promo_code_id je bit-za-bitom enako)", [o1, o2]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE id = ANY($1::bigint[]) AND promo_code_id IS NULL", [[np1.id, np2.id]])).rows[0].n === 2, "promo_code_id obeh narocil je NULL");
    assert((await pool.query("SELECT promo_code_id FROM orders WHERE id=$1", [np3.id])).rows[0].promo_code_id === I.promoKeep, "narocilo z drugo kodo ni spremenjeno");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM promo_codes WHERE id=$1", [P1])).rows[0].n === 0 && (await pool.query("SELECT COUNT(*)::int AS n FROM promo_code_events WHERE promo_code_id=$1", [P1])).rows[0].n === 0, "koda in promo_code_events izbrisana");
    const pS2 = await posnetek(pool);
    assert(razlike(pS1, pS2).join() === "orders,promo_code_events,promo_codes", "spremenijo se SAMO orders (promo_code_id), promo_codes in promo_code_events", razlike(pS1, pS2));
    const fin1 = await api("GET", "/admin/api/finance?from=2020-01-01&to=2030-01-01", T.admin);
    assert(fin0.status === 200 && JSON.stringify(fin0.body.summary) === JSON.stringify(fin1.body.summary) && JSON.stringify(fin0.body.all_time) === JSON.stringify(fin1.body.all_time), "GET /admin/api/finance: pravi promet enak pred in po", [fin0.body.summary, fin1.body.summary]);
    const dp = (await pool.query("SELECT * FROM admin_dejanja WHERE dejanje='promo.delete'")).rows;
    assert(dp.length === 1 && dp[0].cilj_tip === "promo_code" && dp[0].cilj_id === String(P1) && dp[0].admin_user_id === I.admin && dp[0].razlog === "koda ni vec v rabi" && dp[0].prej.code === "BRISI1"
      && dp[0].potem.orders_detached === 2, "admin_dejanja: promo.delete", dp[0]);
    r = await api("GET", "/admin/api/promo-codes", T.admin);
    assert(r.status === 200 && !r.body.some((k) => k.code === "BRISI1"), "koda ni vec na seznamu");
    r = await api("POST", "/admin/api/promo-codes", T.admin, { code: "BRISI1", label: "znova", club_id: D });
    assert(r.status === 201, "isto besedilo kode se da znova ustvariti", r);

    // ============================================================
    console.log("\n# 8. Zaklepanje");
    await omejitveCisti();
    const EL = (await dogodek(pool, D, "Zaklep dogodek", 33)).id;
    const nl = await narocilo(pool, { ev: EL, club: D, user: I.kupec, pi: testPi() });
    const tl = await vstopnica(pool, nl.id, EL);
    // (a) sken, ki ravnokar unovcuje testno vstopnico (UPDATE tickets drzi vrstico): brisanje ne caka v nedogled
    const drzalec = await pool.connect();
    await drzalec.query("BEGIN"); await drzalec.query("SELECT id FROM tickets WHERE id=$1 FOR UPDATE", [tl.id]);
    let t0 = Date.now();
    r = await api("DELETE", `/admin/api/events/${EL}`, T.admin, { reason: "med skeniranjem" });
    assert(r.status === 503 && r.body.error === "busy" && Date.now() - t0 < 4000, "zaseden zapis vstopnice -> 503 busy v nekaj sekundah (lock_timeout)", [r.status, r.body, Date.now() - t0]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE id=$1", [EL])).rows[0].n === 1 && (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE id=$1", [tl.id])).rows[0].n === 1, "nic izbrisano");
    const sken = await drzalec.query("UPDATE tickets SET status='used', used_at=NOW() WHERE id=$1 RETURNING status", [tl.id]);
    assert(sken.rows[0].status === "used", "sken (drzalec zaklepa) lahko dokonca unovcenje: brisanje mu ni vzelo ne zaklepa ne vrstice");
    await drzalec.query("COMMIT"); drzalec.release();
    // (b) nakup v teku: transakcija je ze vstavila PRAVO narocilo (drzi KEY SHARE na vrstici dogodka)
    const nakup = await pool.connect();
    await nakup.query("BEGIN");
    await nakup.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, stripe_checkout_session_id, table_id)
                       VALUES ('OUT-BDLOCK', $1, $2, $3, 1, 1500, 1500, 'pending', 'kupec@example.com', 'cs_live_zaklep', NULL)`, [I.kupec, EL, D]);
    t0 = Date.now();
    r = await api("DELETE", `/admin/api/events/${EL}`, T.admin, { reason: "med nakupom" });
    assert(r.status === 503 && r.body.error === "busy", "nakup v teku drzi dogodek -> 503 busy, nic izbrisano", [r.status, r.body]);
    await nakup.query("COMMIT"); nakup.release();
    r = await api("DELETE", `/admin/api/events/${EL}`, T.admin, { reason: "po nakupu" });
    assert(r.status === 409 && r.body.error === "has_real_orders", "po commit-u nakupa brisanje vidi pravo narocilo v teku -> 409", [r.status, r.body]);
    await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE event_id=$1 AND public_ref='OUT-BDLOCK'", [EL]);
    r = await api("DELETE", `/admin/api/events/${EL}`, T.admin, { reason: "po preklicu nakupa" });
    assert(r.status === 409 && r.body.error === "checkout_may_complete", "preklicano pravo narocilo z odprto Stripe sejo (kupec jo utegne se placati, I37) brisanje ZAVRNE", [r.status, r.body]);
    await pool.query("UPDATE orders SET created_at = NOW() - INTERVAL '5 days', cancelled_at = NOW() - INTERVAL '5 days' WHERE event_id=$1 AND public_ref='OUT-BDLOCK'", [EL]);
    r = await api("DELETE", `/admin/api/events/${EL}`, T.admin, { reason: "seja potekla pred 5 dnevi" });
    assert(r.status === 200 && r.body.deleted === true, "ko je seja dokazano mrtva (brez PI in paid_at, > 3 dni), brisanje uspe", r);
    // (c) izvorna koda
    const koda = fs.readFileSync(path.join(KOREN, "admin_brisanje.js"), "utf8").replace(/\/\/.*$/gm, "");
    assert(!/skenPool/.test(koda), "admin_brisanje.js ne uporablja skenPool (sken ostane pri miru)");
    assert(/lock_timeout/.test(koda) && /statement_timeout/.test(koda), "brisanje ima lock_timeout in statement_timeout");
    for (const f of ["agent_api.js", "agent_predlogi.js"]) {
      const s = fs.readFileSync(path.join(KOREN, f), "utf8");
      assert(!/delete_hard|club\.delete|promo\.delete|delete-check|admin_brisanje/.test(s), `${f}: brisanja NI v agent API-ju in ne na belem seznamu predlogov`);
    }

    // ============================================================
    console.log("\n# 8b. Nakupna pot: promo koda ali dogodek izbrisana med branjem in vpisom narocila (P1)");
    await omejitveCisti();
    await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '25 years')::date WHERE email='kupec@outly.si'");
    {
      const evP = (await dogodek(pool, D, "Nakup med brisanjem", 40)).id;
      const kodaP = (await ins(pool, "promo_codes", { code: "RACE1", label: "tekma", club_id: D, created_by: I.admin })).id;
      // zadrzevalec zaklene vrstico kode; nakup kodo prebere (navaden SELECT), pri vpisu narocila caka na tuji kljuc; zadrzevalec kodo izbrise -> 23503
      const z1 = await pool.connect();
      await z1.query("BEGIN"); await z1.query("SELECT id FROM promo_codes WHERE id=$1 FOR UPDATE", [kodaP]);
      const nakup = api("POST", `/events/${evP}/orders`, T.kupec, { quantity: 1, promo_code: "RACE1" });
      await new Promise((r) => setTimeout(r, 800));
      await z1.query("DELETE FROM promo_codes WHERE id=$1", [kodaP]); await z1.query("COMMIT"); z1.release();
      const rn = await nakup;
      assert(rn.status === 400 && rn.body && rn.body.error === "promo_code_invalid", "izbrisana promo koda med nakupom -> 400 promo_code_invalid (ne 500)", [rn.status, rn.body]);
      assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [evP])).rows[0].n === 0, "narocilo ni nastalo");
      // dogodek izbrisan med nakupom: zadrzevalec zaklene vrstico dogodka, nakup caka (sprozilec rezerviraj_zalogo), zadrzevalec dogodek izbrise -> 404
      const z2 = await pool.connect();
      await z2.query("BEGIN"); await z2.query("SELECT id FROM events WHERE id=$1 FOR UPDATE", [evP]);
      const nakup2 = api("POST", `/events/${evP}/orders`, T.kupec, { quantity: 1 });
      await new Promise((r) => setTimeout(r, 800));
      await z2.query("DELETE FROM events WHERE id=$1", [evP]); await z2.query("COMMIT"); z2.release();
      const rn2 = await nakup2;
      assert(rn2.status === 404, "izbrisan dogodek med nakupom -> 404 (ne 500)", [rn2.status, rn2.body]);
    }

    // ============================================================
    console.log("\n# 9. Omejevalnik");
    await omejitveCisti();
    let kode = [];
    for (let i = 0; i < 22; i++) kode.push((await api("DELETE", "/admin/api/events/999999", T.admin, { reason: "omejevalnik" })).status);
    assert(kode.slice(0, 20).every((s) => s === 404) && kode[20] === 429, "20 klicev v minuti gre skozi (404), 21. -> 429", kode);
    await omejitveCisti();

  } catch (e) {
    fail++; console.log("  ✗ izjema v testu:", e && e.stack || e);
  } finally {
    c.release();
    srv.kill();
    jwksServer.close();
    await pool.end().catch(() => {});
  }
  if (fail) { console.log("\n--- dnevnik backenda ---\n" + log.slice(-3000)); }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
