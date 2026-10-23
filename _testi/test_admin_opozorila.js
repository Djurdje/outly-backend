#!/usr/bin/env node
/**
 * GET /admin/api/opozorila, GET /admin/api/racuni in nova polja v GET /admin/api/summary (#326, 23. 10. 2026; admin_nadzor.js). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_admin_opozorila.js
 * Vzorec kot test_admin_vloga.js: lokalni JWKS (6102), backend na svojem portu (6101), brez predpomnilnika opozoril (ADMIN_NADZOR_PREDPOMNILNIK_MS=0).
 * Backend tece v »zivem« nacinu Stripa (sk_live_ + webhook skrivnost, Stripe se ne klice), da pogoja I34 (podatki prodajalca) in I36/I49 (klub brez Stripa) delujeta.
 *
 * Kaj dokazuje:
 *  1. vsaka vrsta opozorila nastane za dogodek, ki krsi natanko ta pogoj, in izgine, ko se pogoj odpravi (brez_plakata, brez_cene, brez_kapacitete, brez_konca,
 *     prodaja_ustavljena, prodajalec_nepopoln, placila_niso_pripravljena, demo_objavljen, racun_napaka, racun_zaostanek, vracila_pozornost, spori_odprti,
 *     povrnitve_sporov, potrdila_neposlana); stevci rdece/oranzno/rumeno so skladni s seznamom.
 *  2. skriti klub, ze koncan dogodek, osnutek (razen plakata) in dogodki brez kršitve NE dajo opozoril; demo klub je izvzet iz placil (samo demo_objavljen);
 *     brezplacen in zunanji dogodek nista »placila niso pripravljena«; plakat > 14 dni vnaprej ne opozarja; racuni skritega kluba so vidni.
 *  3. odgovor nima nobenega @ (tudi ko zadnja_napaka racuna vsebuje e-naslov), nima e-naslovov, Stripovih ID-jev (acct_, pi_, cs_) ne imen kupcev.
 *  4. GET /admin/api/racuni: filter po stanju, 400 za neznano stanje, meja limit (1..200, neveljavno = 50), stolpci naštevani (brez kupca), zadnja_napaka
 *     skrajsana na 300 znakov in brez e-naslovov, stevci po stanjih.
 *  5. GET /admin/api/summary ima warnings_red (= rdeca opozorila) in racuni_napaka ter VSA stara polja.
 *  6. ne-admin: 403 (user, business, backup), brez zetona 401, na vseh treh poteh.
 *  7. opozorila so samo branje (nobene vrstice v bazi se ne spremenijo) in tecejo na glavnem poolu v READ ONLY transakciji (zapis v pg_stat_statements ni potreben: poizvedbe, ki bi pisale, bi padle).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool, Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6101, JWKS_PORT = 6102;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-opozorila";
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
async function api(method, path, token) {
  const r = await fetch(BASE + path, { method, headers: { ...(token ? { authorization: "Bearer " + token } : {}) } });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t, glave: r.headers };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE racuni, vracila, spori, admin_dejanja, agent_zetoni, omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  // racuni/vracila/spori: vstavljanje v poljubnem stanju (trigger racuni_varuj sicer dovoli samo nov dolg): seja brez sprozilcev, samo za te vstavke
  const brezSprozilcev = new Client({ connectionString: DB });
  await brezSprozilcev.connect();
  await brezSprozilcev.query("SET session_replication_role = replica");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_live_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_lokalno", STRIPE_API_BASE: "http://127.0.0.1:1", TEST_PLACILA: "", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = {
      admin: zeton("admin@outly.si", uuid(1)),
      navaden: zeton("navaden@outly.si", uuid(2)),
      lastnik: zeton("lastnik@outly.si", uuid(3)),
      kopija: zeton("kopija@outly.si", uuid(4)),
    };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET role='backup' WHERE email='kopija@outly.si'");
    const navadenId = (await pool.query("SELECT id FROM users WHERE email='navaden@outly.si'")).rows[0].id;

    // --- klubi (vsak lastnik ima en klub: dodatni lastniki so uporabniki brez prijave) ---
    let st = 100;
    const klub = async (ime, polja = {}) => {
      const moj = st++;
      const u = (await pool.query("INSERT INTO users (email, username, role) VALUES ($1, $2, 'business') RETURNING id", [`lastnik${moj}@primer.si`, `lastnik${moj}`])).rows[0].id;
      const k = { stripe: true, popoln: true, hidden: false, demo: false, ...polja };
      return (await pool.query(
        `INSERT INTO clubs (owner_user_id, name, hidden, is_demo, stripe_account_id, stripe_charges_enabled, stripe_payouts_enabled, stripe_account_livemode,
                            legal_name, legal_address, registration_number, tax_number, vat_payer, contact_email)
         VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id`,
        [u, ime, k.hidden, k.demo, k.stripe ? "acct_skrivni" + moj : null, k.stripe, k.stripe ? true : null,
         k.popoln ? "Klub d.o.o." : "", k.popoln ? "Ulica 1, 1000 Ljubljana" : "", k.popoln ? "1234567" : "", k.popoln ? "SI12345678" : "", k.popoln ? true : null,
         k.popoln ? "info@klub.si" : ""])).rows[0].id;
    };
    const K_OK = await klub("Klub Pripravljen");
    const K_NEPOPOLN = await klub("Klub Nepopoln", { popoln: false });
    const K_BREZ_STRIPA = await klub("Klub Brez Stripa", { stripe: false });
    const K_DEMO = await klub("Klub Demo", { demo: true, popoln: false, stripe: false });
    const K_SKRIT = await klub("Klub Skrit", { hidden: true, popoln: false, stripe: false });

    // --- dogodki: vsak krši natanko eno stvar; osnova je brez kršitev ---
    const dogodek = async (klubId, naslov, polja = {}) => {
      const e = { status: "published", start: "3 days", end: "3 days 6 hours", poster: "https://slike.test/p.jpg", price: 1500, capacity: 100, url: "", paused: false, ...polja };
      return (await pool.query(
        `INSERT INTO events (club_id, title, status, start_at, end_at, poster_url, ticket_price_cents, capacity, ticket_url, sales_paused)
         VALUES ($1, $2, $3, NOW() + $4::interval, CASE WHEN $5::text IS NULL THEN NULL ELSE NOW() + $5::interval END, $6, $7, $8, $9, $10) RETURNING id`,
        [klubId, naslov, e.status, e.start, e.end, e.poster, e.price, e.capacity, e.url, e.paused])).rows[0].id;
    };
    const D = {};
    D.ok = await dogodek(K_OK, "Vse v redu");
    D.plakat = await dogodek(K_OK, "Brez plakata", { poster: "" });
    D.plakatOsnutek = await dogodek(K_OK, "Osnutek brez plakata", { poster: "", status: "draft" });
    D.plakatDaleko = await dogodek(K_OK, "Plakat kasneje", { poster: "", start: "20 days", end: "20 days 6 hours" });
    D.cena = await dogodek(K_OK, "Brez cene", { price: null, capacity: null });
    D.zunanja = await dogodek(K_OK, "Zunanja prodaja", { price: null, capacity: null, url: "https://vstopnice.test/e" });
    D.kapaciteta = await dogodek(K_OK, "Brez kapacitete", { capacity: null });
    D.konec = await dogodek(K_OK, "Brez konca", { end: null });
    D.pavza = await dogodek(K_OK, "Prodaja ustavljena", { paused: true });
    D.prodajalec = await dogodek(K_NEPOPOLN, "Prodajalec nepopoln");
    D.prodajalecOsnutek = await dogodek(K_NEPOPOLN, "Osnutek nepopolnega", { status: "draft" });
    D.prodajalecBrezplacen = await dogodek(K_NEPOPOLN, "Brezplacen pri nepopolnem", { price: 0 });
    D.stripe = await dogodek(K_BREZ_STRIPA, "Klub brez Stripa");
    D.stripeBrezplacen = await dogodek(K_BREZ_STRIPA, "Brezplacen brez Stripa", { price: 0 });
    D.stripeZunanja = await dogodek(K_BREZ_STRIPA, "Zunanja brez Stripa", { price: null, capacity: null, url: "https://vstopnice.test/z" });
    D.demo = await dogodek(K_DEMO, "Demo dogodek");
    D.skrit = await dogodek(K_SKRIT, "Skriti klub vse narobe", { poster: "", price: null, capacity: null, end: null, paused: true });
    D.skritPlacljiv = await dogodek(K_SKRIT, "Skriti placljiv");
    D.koncan = await dogodek(K_NEPOPOLN, "Ze koncan", { start: "-3 days", end: "-2 days -18 hours", poster: "", paused: true });

    // --- racuni (naročila skritega kluba: racuni so vidni kljub skritosti) ---
    let ref = 1;
    const narocilo = async (eventId, klubId, polja = {}) => {
      const o = { status: "paid", paid: "-2 hours", created: "-2 hours", qty: 1, price: 1500, userId: navadenId, receipt: null, pi: null, session: null, listId: null, email: "kupec.zasebni@primer.si", ...polja };
      return (await pool.query(
        `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, created_at, paid_at,
                             receipt_mail_attempts, stripe_payment_intent_id, stripe_checkout_session_id, guest_list_id)
         VALUES ($1, $2, $3::int, $4::int, $5::int, $6::int, $5::int * $6::int, $7, $8, NOW() + $9::interval, CASE WHEN $10::text IS NULL THEN NULL ELSE NOW() + $10::interval END, $11, $12, $13, $14) RETURNING id`,
        ["OUT-OP-" + (ref++), o.userId, eventId, klubId, o.qty, o.price, o.status, o.email, o.created, o.paid, o.receipt, o.pi, o.session, o.listId])).rows[0].id;
    };
    const racun = async (orderId, stanje, polja = {}) => (await brezSprozilcev.query(
      `INSERT INTO racuni (order_id, vrsta, znesek_cents, stanje, created_at, zadnja_napaka, poskusi)
       VALUES ($1, 'racun', 1500, 'caka', NOW() + $2::interval, $3, 2) RETURNING id`,
      [orderId, polja.created || "0", polja.napaka || null])).rows[0].id;
    // Prehod v stanje z dodeljeno stevilko (racuni_stevilka_chk): potrjen = izdan + EOR; napaka lahko ostane brez ali s stevilko.
    const potrdiRacune = (ids) => brezSprozilcev.query(
      `UPDATE racuni SET stanje = 'potrjen', eor = gen_random_uuid(), potrjen_at = NOW(), prostor = 'A001', naprava = '1', leto = 2026, stevilka = 1000 + id, izdan_at = NOW() WHERE id = ANY($1)`, [ids]);
    const vStanje = (ids, stanje) => brezSprozilcev.query("UPDATE racuni SET stanje = $2 WHERE id = ANY($1)", [ids, stanje]);
    // Narocila skritega kluba (K_SKRIT) so »lastna« zgolj za racune; tickete ne potrebujemo.
    const nSkrit1 = await narocilo(D.skritPlacljiv, K_SKRIT, { qty: 1 });
    const nSkrit2 = await narocilo(D.skritPlacljiv, K_SKRIT, { qty: 1 });
    const nSkrit3 = await narocilo(D.skritPlacljiv, K_SKRIT, { qty: 1 });
    const nSkrit4 = await narocilo(D.skritPlacljiv, K_SKRIT, { qty: 1 });
    const nSkrit5 = await narocilo(D.skritPlacljiv, K_SKRIT, { qty: 1 });
    const nSkrit6 = await narocilo(D.skritPlacljiv, K_SKRIT, { qty: 1 });
    const DOLGA_NAPAKA = "e-racuni: zavrnjeno za kupec.zasebni@primer.si in @drugi (" + "x".repeat(400) + ")";
    const R = {};
    R.napaka = await racun(nSkrit1, "caka", { napaka: "Kupec kupec.zasebni@primer.si: fiscalization failed" });
    R.napakaDolga = await racun(nSkrit2, "caka", { napaka: DOLGA_NAPAKA });
    R.caka1 = await racun(nSkrit3, "caka", { created: "-2 hours" });
    R.caka2 = await racun(nSkrit4, "caka", { created: "-3 hours" });
    R.cakaSvez = await racun(nSkrit5, "caka", { created: "-5 minutes" });
    R.potrjen = await racun(nSkrit6, "caka");
    for (const id of [R.napaka, R.napakaDolga]) await vStanje([id], "napaka");
    await potrdiRacune([R.potrjen]);
    // naročilo za neposlano potrdilo, vracilo in spor
    const nPotrdilo = await narocilo(D.ok, K_OK, { receipt: 0 });
    const nPotrdiloPoslano = await narocilo(D.ok, K_OK, { receipt: 1 });
    await pool.query("UPDATE orders SET receipt_mail_sent_at = NOW() WHERE id = $1", [nPotrdiloPoslano]);
    const nPotrdiloSvez = await narocilo(D.ok, K_OK, { receipt: 0, paid: "-10 minutes", created: "-10 minutes" });
    const nPotrdiloIzbrisan = await narocilo(D.ok, K_OK, { receipt: 8, email: "izbrisan@outly.invalid" });
    await pool.query("UPDATE orders SET receipt_mail_attempts = 0 WHERE id = $1", [nPotrdiloIzbrisan]);
    const nVracilo = await narocilo(D.ok, K_OK, { pi: "pi_skrivni456", session: "cs_live_skrivni789" });

    const dobi = async (pot = "/admin/api/opozorila") => api("GET", pot, T.admin);
    // summary NE sprozi izracuna opozoril: na svezem strezniku (se noben klic /opozorila ali /danes) je warnings_red null, tudi ob ponovnem klicu
    let sv = await dobi("/admin/api/summary");
    assert(sv.status === 200 && sv.body.warnings_red === null, "svez streznik: summary.warnings_red je null (izracuna ne sprozi)", sv.body.warnings_red);
    sv = await dobi("/admin/api/summary");
    assert(sv.body.warnings_red === null, "ponovni summary je se vedno null (se vedno brez izracuna)", sv.body.warnings_red);
    const ima = (items, vrsta, cilj_id) => items.some(i => i.vrsta === vrsta && (cilj_id === undefined || String(i.cilj_id) === String(cilj_id)));
    const stevci = (items) => { const s = { rdece: 0, oranzno: 0, rumeno: 0 }; for (const i of items) s[i.resnost]++; return s; };

    console.log("\n# Vsaka vrsta opozorila nastane");
    let r = await dobi();
    assert(r.status === 200 && Array.isArray(r.body.items) && r.body.stevci && typeof r.body.stevci.rdece === "number", "200, oblika { items, stevci }", r.status);
    const items = r.body.items;
    assert(r.glave.get("cache-control") === "no-store", "Cache-Control: no-store");
    for (const i of items) {
      assert(["vrsta", "resnost", "cilj_tip", "cilj_id", "besedilo"].every(k => k in i) && ["rdece", "oranzno", "rumeno"].includes(i.resnost) && typeof i.besedilo === "string" && i.besedilo.length > 0,
        `postavka ${i.vrsta}/${i.cilj_id}: vsa polja, veljavna resnost`, i);
    }
    assert(ima(items, "racun_napaka", R.napaka) && ima(items, "racun_napaka", R.napakaDolga), "racun_napaka: oba racuna v stanju napaka (skriti klub NE skrije racunov)");
    assert(items.filter(i => i.vrsta === "racun_napaka").every(i => i.resnost === "rdece" && i.cilj_tip === "racun"), "racun_napaka: rdece, cilj_tip racun");
    assert(items.find(i => i.vrsta === "racun_napaka").besedilo.includes("Davčno potrjeni računi"), "racun_napaka: besedilo omeni rocni postopek v STATE");
    const zaostanek = items.filter(i => i.vrsta === "racun_zaostanek");
    assert(zaostanek.length === 1 && zaostanek[0].resnost === "oranzno" && zaostanek[0].besedilo.startsWith("2 "), "racun_zaostanek: ena vrstica s stevilom 2 (cakata > 1 h; svez racun ne steje)", zaostanek);
    assert(ima(items, "brez_plakata", D.plakat) && ima(items, "brez_plakata", D.plakatOsnutek), "brez_plakata: objavljen IN osnutek (zacetek v 14 dneh)");
    assert(!ima(items, "brez_plakata", D.plakatDaleko), "brez_plakata: dogodek cez 20 dni ne opozarja");
    assert(ima(items, "brez_cene", D.cena) && !ima(items, "brez_cene", D.zunanja) && !ima(items, "brez_cene", D.stripeZunanja), "brez_cene: brez cene in brez zunanje prodaje; zunanja prodaja je v redu");
    assert(ima(items, "brez_kapacitete", D.kapaciteta) && !ima(items, "brez_kapacitete", D.cena) && !ima(items, "brez_kapacitete", D.zunanja), "brez_kapacitete: samo placljiv (cena > 0) brez kapacitete");
    assert(ima(items, "brez_konca", D.konec), "brez_konca");
    assert(ima(items, "prodaja_ustavljena", D.pavza), "prodaja_ustavljena");
    assert(ima(items, "prodajalec_nepopoln", D.prodajalec) && items.find(i => i.vrsta === "prodajalec_nepopoln").resnost === "rdece", "prodajalec_nepopoln (I34): rdece");
    assert(!ima(items, "prodajalec_nepopoln", D.prodajalecOsnutek) && !ima(items, "prodajalec_nepopoln", D.prodajalecBrezplacen), "prodajalec_nepopoln: osnutek in brezplacen dogodek (0 EUR gre mimo I34) ne opozarjata");
    assert(ima(items, "placila_niso_pripravljena", D.stripe) && items.find(i => i.vrsta === "placila_niso_pripravljena").resnost === "rdece", "placila_niso_pripravljena (I36/I49): klub brez Stripa, rdece");
    assert(!ima(items, "placila_niso_pripravljena", D.stripeBrezplacen), "placila_niso_pripravljena: brezplacen dogodek brez Stripa je kupljiv (I49)");
    assert(ima(items, "demo_objavljen", D.demo) && !ima(items, "prodajalec_nepopoln", D.demo) && !ima(items, "placila_niso_pripravljena", D.demo), "demo_objavljen (rumeno); demo klub je izvzet iz obeh placilnih opozoril");
    assert(items.find(i => i.vrsta === "demo_objavljen").resnost === "rumeno", "demo_objavljen: rumeno");
    assert(ima(items, "potrdila_neposlana") && items.find(i => i.vrsta === "potrdila_neposlana").besedilo.startsWith("1 "), "potrdila_neposlana: natanko 1 (poslano, svezo in @outly.invalid ne steje)", items.filter(i => i.vrsta === "potrdila_neposlana"));
    assert(!ima(items, "vracila_pozornost") && !ima(items, "spori_odprti") && !ima(items, "povrnitve_sporov"), "brez vracil in sporov v bazi: teh opozoril ni");

    console.log("\n# Kar ne sme dati opozorila");
    const dogodkiId = new Set(items.filter(i => i.cilj_tip === "dogodek").map(i => String(i.cilj_id)));
    assert(!dogodkiId.has(String(D.ok)), "dogodek brez krsitev nima opozoril");
    assert(!dogodkiId.has(String(D.skrit)) && !dogodkiId.has(String(D.skritPlacljiv)), "skriti klub: nobenega opozorila za njegove dogodke");
    assert(!dogodkiId.has(String(D.koncan)), "ze koncan dogodek nima opozoril");
    const pricakovano = [["brez_plakata", D.plakat], ["brez_plakata", D.plakatOsnutek], ["brez_cene", D.cena], ["brez_kapacitete", D.kapaciteta], ["brez_konca", D.konec],
      ["prodaja_ustavljena", D.pavza], ["prodajalec_nepopoln", D.prodajalec], ["placila_niso_pripravljena", D.stripe], ["demo_objavljen", D.demo]];
    const dogodkovnih = items.filter(i => i.cilj_tip === "dogodek").map(i => `${i.vrsta}:${i.cilj_id}`).sort();
    assert(JSON.stringify(dogodkovnih) === JSON.stringify(pricakovano.map(([v, id]) => `${v}:${id}`).sort()), "natanko pricakovana mnozica dogodkovnih opozoril (nobenega odvecnega)", dogodkovnih);
    assert(JSON.stringify(r.body.stevci) === JSON.stringify(stevci(items)), "stevci = stetje seznama", [r.body.stevci, stevci(items)]);
    assert(r.body.stevci.rdece === 4, "rdece: 2 racuna napaka + prodajalec + placila = 4", r.body.stevci);

    console.log("\n# Brez osebnih podatkov");
    assert(!r.text.includes("@"), "v odgovoru ni znaka @ (zadnja_napaka z e-naslovom ni v opozorilih)");
    for (const prepovedano of ["kupec.zasebni", "primer.si", "acct_", "pi_skrivni", "cs_live", "skrivni", "outly.invalid"]) {
      assert(!r.text.includes(prepovedano), `v odgovoru ni »${prepovedano}«`);
    }

    console.log("\n# Opozorila izginejo, ko se kršitev odpravi");
    const popravki = [
      ["brez_plakata", D.plakat, "UPDATE events SET poster_url = 'https://x.test/p.jpg' WHERE id = $1"],
      ["brez_plakata", D.plakatOsnutek, "UPDATE events SET poster_url = 'https://x.test/p.jpg' WHERE id = $1"],
      ["brez_cene", D.cena, "UPDATE events SET ticket_url = 'https://vstopnice.test/x' WHERE id = $1"],
      ["brez_kapacitete", D.kapaciteta, "UPDATE events SET capacity = 50 WHERE id = $1"],
      ["brez_konca", D.konec, "UPDATE events SET end_at = start_at + INTERVAL '6 hours' WHERE id = $1"],
      ["prodaja_ustavljena", D.pavza, "UPDATE events SET sales_paused = FALSE WHERE id = $1"],
      ["prodajalec_nepopoln", D.prodajalec, "UPDATE clubs SET legal_name = 'Nepopolni d.o.o.', legal_address = 'Cesta 2, 2000 Maribor', registration_number = '7654321', tax_number = 'SI87654321', vat_payer = FALSE, contact_email = 'k@k.si' WHERE id = (SELECT club_id FROM events WHERE id = $1)"],
      ["placila_niso_pripravljena", D.stripe, "UPDATE clubs SET stripe_account_id = 'acct_x', stripe_charges_enabled = TRUE, stripe_account_livemode = TRUE WHERE id = (SELECT club_id FROM events WHERE id = $1)"],
      ["demo_objavljen", D.demo, "UPDATE events SET status = 'draft' WHERE id = $1"],
    ];
    let prej = (await dobi()).body.items.length;
    for (const [vrsta, id, sql] of popravki) {
      await pool.query(sql, [id]);
      const po = (await dobi()).body.items;
      assert(!ima(po, vrsta, id), `${vrsta} (dogodek ${id}) izgine po popravku`);
      assert(po.length === prej - 1, `${vrsta}: odpade natanko ena postavka (ostalih ni zmotilo)`, [prej, po.length]);
      prej = po.length;
    }
    // popravek kluba nepopolni -> zdaj popoln: edini dogodek tega kluba (D.prodajalec) je izginil; ostane racun/vracila/potrdila

    console.log("\n# Racuni: napaka/zaostanek izgineta");
    await potrdiRacune([R.napaka, R.napakaDolga]);
    let po = (await dobi()).body.items;
    assert(!ima(po, "racun_napaka"), "racun_napaka izgine, ko racuna nista vec v napaki");
    await brezSprozilcev.query("UPDATE racuni SET created_at = NOW() - INTERVAL '30 minutes' WHERE id = ANY($1)", [[R.caka1, R.caka2]]);
    po = (await dobi()).body.items;
    assert(!ima(po, "racun_zaostanek"), "racun_zaostanek izgine, ko noben racun ne caka > 1 h");
    await brezSprozilcev.query("UPDATE racuni SET created_at = NOW() - INTERVAL '90 minutes' WHERE id = $1", [R.caka1]);
    po = (await dobi()).body.items;
    assert(ima(po, "racun_zaostanek") && po.find(i => i.vrsta === "racun_zaostanek").besedilo.startsWith("1 "), "racun_zaostanek se vrne (1 racun)");
    await pool.query("UPDATE orders SET receipt_mail_sent_at = NOW() WHERE id = $1", [nPotrdilo]);
    po = (await dobi()).body.items;
    assert(!ima(po, "potrdila_neposlana"), "potrdila_neposlana izgine po poslanem potrdilu");

    console.log("\n# Vracila, spori, povrnitve sporov");
    const vracilo = await brezSprozilcev.query("INSERT INTO vracila (order_id, event_id, razlog, stanje, znesek_cents) VALUES ($1, $2, 'event_cancelled', 'ni_uspelo', 1500) RETURNING id", [nVracilo, D.ok]);
    await brezSprozilcev.query("INSERT INTO spori (id, order_id, stanje, znesek_cents, povrnitev_stanje) VALUES ('dp_1', $1, 'needs_response', 1500, 'rocno'), ('dp_2', $1, 'won', 1500, NULL)", [nVracilo]);
    po = (await dobi()).body.items;
    assert(ima(po, "vracila_pozornost") && po.find(i => i.vrsta === "vracila_pozornost").resnost === "rdece" && po.find(i => i.vrsta === "vracila_pozornost").besedilo.startsWith("1 "), "vracila_pozornost: rdece, 1");
    assert(ima(po, "spori_odprti") && po.find(i => i.vrsta === "spori_odprti").resnost === "oranzno" && po.find(i => i.vrsta === "spori_odprti").besedilo.startsWith("2 "), "spori_odprti: oranzno, 2 (zaprt_at IS NULL)");
    assert(ima(po, "povrnitve_sporov") && po.find(i => i.vrsta === "povrnitve_sporov").resnost === "rdece", "povrnitve_sporov: rdece");
    await brezSprozilcev.query("UPDATE vracila SET stanje = 'opravljeno' WHERE id = $1", [vracilo.rows[0].id]);
    await brezSprozilcev.query("UPDATE spori SET zaprt_at = NOW(), povrnitev_stanje = 'opravljeno'");
    po = (await dobi()).body.items;
    assert(!ima(po, "vracila_pozornost") && !ima(po, "spori_odprti") && !ima(po, "povrnitve_sporov"), "vracila in spori izginejo, ko so urejeni");
    assert(!(await dobi()).text.includes("pi_skrivni") && !(await dobi()).text.includes("cs_live"), "Stripovi ID-ji naročila ne uidejo");

    console.log("\n# GET /admin/api/racuni");
    r = await dobi("/admin/api/racuni");
    assert(r.status === 200 && Array.isArray(r.body.items) && r.body.stevci && r.body.limit === 50, "brez filtra: 200, { stevci, limit: 50, items }", [r.status, r.body.limit]);
    assert(r.body.items.length === 6, "brez filtra: vseh 6 racunov", r.body.items.length);
    const STOLPCI = ["id", "order_id", "vrsta", "stanje", "znesek_cents", "valuta", "stevilka", "ponudnik_stevilka", "izdan_at", "potrjen_at", "poskusi", "zadnja_napaka", "created_at"];
    assert(r.body.items.every(x => JSON.stringify(Object.keys(x).sort()) === JSON.stringify([...STOLPCI].sort())), "stolpci so natanko naštete (brez kupca, brez e-naslova)", Object.keys(r.body.items[0]));
    assert(r.body.items.every((x, i, a) => i === 0 || a[i - 1].id > x.id), "najnovejsi racun prvi (id padajoce)");
    assert(JSON.stringify(r.body.stevci) === JSON.stringify({ caka: 3, izdan: 0, potrjen: 3, napaka: 0, preklican: 0 }), "stevci po stanjih", r.body.stevci);
    assert(r.body.items.every(x => x.valuta === "EUR" && x.znesek_cents === 1500), "valuta EUR (brez presledkov), znesek v centih");
    // napaka: vrni racuna v napako in preveri sanacijo zadnje_napake
    await brezSprozilcev.query("UPDATE racuni SET stanje = 'napaka' WHERE id = ANY($1)", [[R.napaka, R.napakaDolga]]);
    r = await dobi("/admin/api/racuni?stanje=napaka");
    assert(r.status === 200 && r.body.items.length === 2 && r.body.items.every(x => x.stanje === "napaka"), "stanje=napaka: samo racuna v napaki", r.body.items.map(x => x.stanje));
    assert(!r.text.includes("@"), "racuni: v odgovoru ni @");
    assert(!r.text.includes("kupec.zasebni") && !r.text.includes("primer.si"), "racuni: e-naslov iz zadnje_napake je odstranjen");
    const kratka = r.body.items.find(x => String(x.id) === String(R.napaka)), dolga = r.body.items.find(x => String(x.id) === String(R.napakaDolga));
    assert(kratka.zadnja_napaka === "Kupec [e-naslov]: fiscalization failed", "zadnja_napaka: e-naslov zamenjan z [e-naslov]", kratka.zadnja_napaka);
    assert(dolga.zadnja_napaka.length === 300 && dolga.zadnja_napaka.startsWith("e-racuni: zavrnjeno za [e-naslov] in [e-naslov] ("), "zadnja_napaka: skrajsana na 300 znakov, e-naslov in goli @ zamenjana", dolga.zadnja_napaka.slice(0, 80));
    assert(r.body.items.every(x => x.poskusi === 2), "poskusi vrnjeni");
    for (const s of ["caka", "izdan", "potrjen", "preklican"]) {
      r = await dobi("/admin/api/racuni?stanje=" + s);
      assert(r.status === 200 && r.body.items.every(x => x.stanje === s), `stanje=${s}: samo to stanje`, r.body.items && r.body.items.map(x => x.stanje));
    }
    r = await dobi("/admin/api/racuni?stanje=caka");
    assert(r.body.items.length === 3, "stanje=caka: trije", r.body.items.length);
    r = await dobi("/admin/api/racuni?stanje=nekaj");
    assert(r.status === 400, "neznano stanje -> 400", r.status);
    r = await dobi("/admin/api/racuni?limit=2");
    assert(r.body.items.length === 2 && r.body.limit === 2, "limit=2: dva racuna", r.body.items.length);
    r = await dobi("/admin/api/racuni?limit=1");
    assert(r.body.items.length === 1, "limit=1: en racun");
    r = await dobi("/admin/api/racuni?limit=0");
    assert(r.status === 200 && r.body.limit === 50, "limit=0 -> privzeto 50", r.body.limit);
    r = await dobi("/admin/api/racuni?limit=abc");
    assert(r.status === 200 && r.body.limit === 50, "limit=abc -> privzeto 50", r.body.limit);
    r = await dobi("/admin/api/racuni?limit=-5");
    assert(r.status === 200 && r.body.limit === 1, "limit=-5 -> 1", r.body.limit);
    r = await dobi("/admin/api/racuni?limit=100000");
    assert(r.status === 200 && r.body.limit === 200, "limit=100000 -> meja 200", r.body.limit);
    // meja 200 na dejanskih vrsticah
    await brezSprozilcev.query(
      `WITH o AS (INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
                  SELECT 'OUT-BULK-' || g, $1, $2, 1, 1500, 1500, 'paid', 'x@y.si', NOW() FROM generate_series(1, 230) g RETURNING id)
       INSERT INTO racuni (order_id, vrsta, znesek_cents, stanje) SELECT id, 'racun', 1500, 'caka' FROM o`, [D.skritPlacljiv, K_SKRIT]);
    r = await dobi("/admin/api/racuni?limit=100000");
    assert(r.body.items.length === 200, "230 racunov, limit=100000: vrnjenih natanko 200", r.body.items.length);
    assert(r.body.stevci.caka === 233, "stevci steje vse, ne samo prikazanih (233 caka)", r.body.stevci);

    console.log("\n# GET /admin/api/summary");
    const op = (await dobi()).body;   // izracun opozoril; summary nato vzame zadnje stevilo
    r = await dobi("/admin/api/summary");
    const STARA = ["new_applications", "clubs", "hidden_clubs", "users", "business_users", "admins", "events", "upcoming_events", "open_reports", "refunds_attention", "open_disputes", "dispute_recovery_attention"];
    assert(r.status === 200 && STARA.every(k => typeof r.body[k] === "number"), "vsa stara polja summary so se vedno tu (stevila)", STARA.filter(k => typeof r.body[k] !== "number"));
    assert(r.body.racuni_napaka === 2, "racuni_napaka = 2", r.body.racuni_napaka);
    assert(typeof r.body.warnings_red === "number" && r.body.warnings_red === op.stevci.rdece, "warnings_red = stevilo rdecih opozoril", [r.body.warnings_red, op.stevci.rdece]);
    assert(r.body.warnings_red >= 2, "warnings_red vkljucuje racuna v napaki", r.body.warnings_red);

    console.log("\n# Vloge");
    for (const pot of ["/admin/api/opozorila", "/admin/api/racuni", "/admin/api/racuni?stanje=napaka", "/admin/api/summary"]) {
      for (const [ime, t, status] of [["user", T.navaden, 403], ["business", T.lastnik, 403], ["backup", T.kopija, 403], ["brez zetona", null, 401]]) {
        const x = await api("GET", pot, t);
        assert(x.status === status, `${ime}: GET ${pot} -> ${status}`, x.status);
      }
    }

    console.log("\n# Dolg naslov (#330 K1): besedila se odrezejo ze v SQL");
    {
      const dolg = await dogodek(K_OK, "D".repeat(95000), { poster: "", start: "2 hours", end: "8 hours" });   // brez plakata + nocoj: naslov je v opozorilih in v »danes«
      const [op2, dn2] = [await dobi(), await dobi("/admin/api/danes")];
      assert(op2.status === 200 && dn2.status === 200, "dogodek z naslovom 95 000 znakov: /opozorila in /danes 200", [op2.status, dn2.status]);
      const o2 = op2.body.items.find((x) => x.cilj_tip === "dogodek" && x.cilj_id === dolg && x.vrsta === "brez_plakata");
      assert(o2 && o2.besedilo.length <= 200 && o2.besedilo.includes("D".repeat(80)) && !o2.besedilo.includes("D".repeat(81)), "opozorilo: naslov odrezan na 80 znakov", o2 && o2.besedilo.length);
      const n2 = dn2.body.nocoj.find((x) => x.id === dolg);
      assert(n2 && n2.naslov === "D".repeat(200), "danes: naslov odrezan na 200 znakov", n2 && n2.naslov.length);
      assert(op2.text.length < 100000 && dn2.text.length < 100000, "odgovora nista veliko daljsa od ostalih (ni prenosa 95 000 znakov v odgovor)", [op2.text.length, dn2.text.length]);
      await pool.query("DELETE FROM events WHERE id = $1", [dolg]);
    }

    console.log("\n# Samo branje");
    const pred = JSON.stringify((await pool.query("SELECT (SELECT COUNT(*) FROM events) e, (SELECT COUNT(*) FROM orders) o, (SELECT COUNT(*) FROM admin_dejanja) a, (SELECT COUNT(*) FROM racuni) r")).rows[0]);
    for (let i = 0; i < 3; i++) { await dobi(); await dobi("/admin/api/racuni"); }
    const potem = JSON.stringify((await pool.query("SELECT (SELECT COUNT(*) FROM events) e, (SELECT COUNT(*) FROM orders) o, (SELECT COUNT(*) FROM admin_dejanja) a, (SELECT COUNT(*) FROM racuni) r")).rows[0]);
    assert(pred === potem, "klici ne spremenijo stevila vrstic (events, orders, admin_dejanja, racuni)", [pred, potem]);
    assert(!/Error|TypeError|ReferenceError|Unhandled/.test(log.replace(/racuni_varuj/g, "")), "dnevnik streznika brez napak", log.split("\n").filter(l => /Error|Unhandled/.test(l)).slice(0, 3));
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
  } finally {
    srv.kill();
    jwksServer.close();
    await brezSprozilcev.end().catch(() => {});
    await pool.end().catch(() => {});
  }
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
