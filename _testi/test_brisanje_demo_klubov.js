#!/usr/bin/env node
/**
 * Test: migracija 066_brisanje_demo_klubov.sql (Martin, 23. 10. 2026: izbrisi demo klube in vse njihove dogodke; Outly in QUICKIE ne smeta izginiti).
 *
 * Sveza baza outly_brisanje_<pid> (ostalih ne dotakne): migrate.js --do 065, nato podatki, ki posnemajo produkcijo:
 *   - 5 demo klubov (is_demo, skriti) s 15 dogodki, testnimi narocili (lazni nacin, sandbox cs_test_), VIP mizo + paketom + streZbo, guest listo,
 *     gost zetoni, prenosom vstopnice, vracili testnega narocila, promo kodo, ogledi, sledilci, ekipo, vabili, prijavami, predlogom agenta;
 *   - klub Outly (ni demo) z dogodkoma QUICKIE (objavljen) in Launch Party (odpovedan), PRAVIMI placanimi narocili, racunom, sporom, Stripovim vracilom,
 *     VIP mizo, guest listo ... — vse to mora ostati bit-za-bitom;
 *   - stari pravi klub brez dogodkov (is_demo = FALSE) mora ostati.
 *
 * Preveri: (1) varovala (a)-(c) migracijo ustavijo in NIC se ne spremeni (vsako v svoji transakciji, ki se vrne nazaj);
 * (2) pravi zagon z db/migrate.js: demo klubi, dogodki in vse odvisne vrstice izginejo, vse ostalo je enako (md5 vrstic po tabelah), uporabniki ostanejo,
 * v dnevniku so stevila; (3) ponovni zagon ne naredi nicesar; (4) javni API in GET /me po brisanju; (5) na prazni bazi (sveza migracija) migracija ne naredi nicesar.
 *
 * Zagon (lokalno, PG16):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_brisanje_demo_klubov.js
 * Backend na 3139, lokalni JWKS na 3999.
 */
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { spawn, spawnSync } = require("child_process");
const { Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const KOREN = path.join(__dirname, "..");
const PORT = 3139, JWKS_PORT = 3999;
const BASE = `http://127.0.0.1:${PORT}`;
const IME_BAZE = `outly_brisanje_${process.pid}`;
const IME_PRAZNE = `outly_brisanje_prazna_${process.pid}`;
const vzdUrl = new URL(DB); vzdUrl.pathname = "/postgres";
const urlBaze = (ime) => { const u = new URL(DB); u.pathname = "/" + ime; return u; };
const ssl = DB.includes("localhost") ? false : { rejectUnauthorized: false };

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

// --- JWKS + zetoni (kot test_vabila.js) ---
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-brisanje";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
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
async function api(p, token) {
  const r = await fetch(BASE + p, { headers: token ? { authorization: "Bearer " + token } : {} });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

// Isto kot migrate.js: brez vrstic BEGIN;/COMMIT; (zavijemo sami).
const brezTransakcije = (ime) => fs.readFileSync(path.join(KOREN, "db", "migracije", ime), "utf8")
  .split("\n").filter((v) => !/^\s*(BEGIN|COMMIT)\s*;\s*$/i.test(v)).join("\n");
const SQL066 = brezTransakcije("066_brisanje_demo_klubov.sql");

async function odjemalec(url) { const c = new Client({ connectionString: url.toString(), ssl }); c.on("error", () => {}); await c.connect(); return c; }
function migrate(url, args = []) {
  const r = spawnSync(process.execPath, ["db/migrate.js", ...args], { cwd: KOREN, env: { ...process.env, NODE_ENV: "test", DATABASE_URL: url.toString() }, encoding: "utf8", timeout: 180000 });
  return { koda: r.status, izpis: (r.stdout || "") + (r.stderr || "") };
}

// Vstavi vrstico in vrne jo (stolpci iz objekta; JSONB polja po imenu).
const JSONB = new Set(["spremembe"]);
async function ins(c, tab, o) {
  const k = Object.keys(o);
  const sql = `INSERT INTO ${tab} (${k.join(",")}) VALUES (${k.map((x, i) => "$" + (i + 1) + (JSONB.has(x) ? "::jsonb" : "")).join(",")}) RETURNING *`;
  return (await c.query(sql, k.map((x) => (JSONB.has(x) ? JSON.stringify(o[x]) : o[x])))).rows[0];
}
let stNar = 0;
async function narocilo(c, o) {
  stNar++;
  const kolicina = o.quantity ?? 1, cena = o.unit ?? 1500;
  return ins(c, "orders", {
    public_ref: `OUT-BR${String(stNar).padStart(4, "0")}`, user_id: o.user ?? null, event_id: o.ev, club_id: o.club, quantity: kolicina,
    unit_price_cents: cena, total_cents: cena * kolicina, status: o.status ?? "paid", buyer_email: o.email ?? "kupec@example.com",
    paid_at: (o.status ?? "paid") === "paid" || o.status === "refunded" ? new Date() : null, stripe_payment_intent_id: o.pi ?? null,
    stripe_checkout_session_id: o.seja ?? null, stripe_account_id: o.acct ?? null, application_fee_cents: o.fee ?? 0, refunded_cents: o.refunded ?? 0,
    table_id: o.tableId ?? null, table_label: o.tableLabel ?? null, table_seats: o.tableSeats ?? null, package_id: o.packageId ?? null, package_name: o.packageName ?? null,
    guest_list_id: o.guestListId ?? null, promo_code_id: o.promo ?? null, cancelled_at: o.status === "cancelled" ? new Date() : null,
    ...(o.guest ? { guest_email: "gost@example.com", guest_terms_version: "v1", guest_terms_accepted_at: new Date() } : {}),
  });
}
const vstopnica = (c, ord, ev, status = "valid") => ins(c, "tickets", { order_id: ord, event_id: ev, status, ...(status === "used" ? { used_at: new Date() } : {}) });
const dogodek = (c, klub, naslov, pomik, status = "published", extra = {}) => ins(c, "events", {
  club_id: klub, title: naslov, poster_url: "https://example.com/p.jpg", start_at: new Date(Date.now() + pomik * 864e5), status,
  ticket_price_cents: 1500, genres: ["balkan"], vip_enabled: true, ...extra });
const hex = (n) => crypto.createHash("sha256").update("t" + n).digest("hex");

// ---------------------------------------------------------------- podatki
async function podatki(c) {
  const I = { demoKlubi: [], demoDogodki: [], uporabniki: {} };
  let nu = 0;
  const uporabnik = async (email, vloga = "user") => {
    nu++;
    const u = await ins(c, "users", { email, username: email.split("@")[0], role: vloga, email_verified: true, supabase_uid: uuid(nu) });
    I.uporabniki[email] = { id: u.id, uid: uuid(nu) };
    return u.id;
  };
  const kupec = await uporabnik("kupec@example.com");
  const kupec2 = await uporabnik("kupec2@example.com");
  const clanDemo = await uporabnik("clan.demo@example.com");        // clan samo demo kluba -> ostane brez kluba
  const clanObe = await uporabnik("clan.obe@example.com");          // clan demo kluba IN Outlyja -> ostane clan Outlyja
  const lastnikOutly = await uporabnik("lastnik.outly@example.com", "business");
  const lastnikStari = await uporabnik("lastnik.stari@example.com", "business");
  const admin = await uporabnik("admin@example.com", "admin");
  I.kupec = kupec; I.lastnikOutly = lastnikOutly; I.admin = admin;
  const imenaDemo = ["Velvet", "Nexus", "Mirage", "Mansion", "Olie"];
  const lastnikiDemo = [];
  for (const ime of imenaDemo) lastnikiDemo.push(await uporabnik(`lastnik.${ime.toLowerCase()}@example.com`, "business"));
  I.lastnikiDemo = lastnikiDemo;

  // --- klubi
  for (let i = 0; i < 5; i++) {
    const k = await ins(c, "clubs", { owner_user_id: lastnikiDemo[i], name: imenaDemo[i], city: "Ljubljana", hidden: true, is_demo: true,
      contact_email: `${imenaDemo[i].toLowerCase()}@example.com`, genres: ["balkan"], logo_url: `https://outly.si/assets/clubs/${imenaDemo[i].toLowerCase()}.jpg` });
    I.demoKlubi.push(k.id);
  }
  const outly = await ins(c, "clubs", { owner_user_id: lastnikOutly, name: "Outly", city: "Ljubljana", is_organizer: true, stripe_account_id: "acct_outly",
    stripe_charges_enabled: true, stripe_payouts_enabled: true, legal_name: "Outly d.o.o." });
  const stari = await ins(c, "clubs", { owner_user_id: lastnikStari, name: "Stari pravi klub", city: "Maribor" });
  I.outly = outly.id; I.stari = stari.id;

  // --- ekipa in sledilci
  await ins(c, "club_members", { club_id: I.demoKlubi[0], user_id: clanDemo, role: "doorman" });
  await ins(c, "club_members", { club_id: I.demoKlubi[1], user_id: clanObe, role: "doorman" });
  await ins(c, "club_members", { club_id: I.outly, user_id: clanObe, role: "doorman" });
  await ins(c, "club_invites", { club_id: I.demoKlubi[0], user_id: kupec2, role: "manager" });
  await ins(c, "club_invites", { club_id: I.outly, user_id: kupec2, role: "manager" });
  await ins(c, "club_follows", { club_id: I.demoKlubi[0], user_id: kupec });
  await ins(c, "club_follows", { club_id: I.outly, user_id: kupec });

  // --- dogodki demo klubov: pretekli, prihodnji, odpovedan (trigger zapise odpovedi_dogodkov)
  const dem = [];
  for (let i = 0; i < 5; i++) {
    const k = I.demoKlubi[i];
    const p = await dogodek(c, k, `${imenaDemo[i]} pretekli`, -10), f = await dogodek(c, k, `${imenaDemo[i]} prihodnji`, 10), o = await dogodek(c, k, `${imenaDemo[i]} odpovedan`, 5, "cancelled");
    dem.push({ p, f, o });
    I.demoDogodki.push(p.id, f.id, o.id);
    await ins(c, "view_counts", { club_id: k, day: "2026-10-01", count: 3 });
    await ins(c, "view_counts", { club_id: k, event_id: p.id, day: "2026-10-01", count: 2 });
  }
  I.demo = dem;
  const e1 = dem[0].p, e1o = dem[0].o;
  await ins(c, "event_favorites", { user_id: kupec, event_id: e1.id });
  await ins(c, "event_interest", { user_id: kupec, event_id: e1.id });
  await ins(c, "club_event_notifications", { user_id: kupec, event_id: e1.id });

  // --- demo: mize, paketi, tloris
  const miza1 = await ins(c, "club_tables", { club_id: I.demoKlubi[0], label: "D1", x: 1, y: 1, w: 2, h: 2, seats: 6, price_cents: 30000 });
  const paket1 = await ins(c, "bottle_packages", { club_id: I.demoKlubi[0], name: "Jameson", description: "demo" });
  await ins(c, "event_tables", { event_id: e1.id, table_id: miza1.id });
  await ins(c, "table_holds", { event_id: e1.id, table_id: miza1.id, guest_name: "Demo gost" });
  I.demoMiza = miza1.id; I.demoPaket = paket1.id;
  const promoDemo = await ins(c, "promo_codes", { code: "DEMOPROMO", label: "Demo", club_id: I.demoKlubi[0], created_by: admin });
  await ins(c, "promo_code_events", { promo_code_id: promoDemo.id, event_id: e1.id });

  // --- demo: testna narocila (lazni nacin, sandbox), VIP s strezbo, gost, guest lista, vracilo, pravi failed/cancelled
  const nLazni = await narocilo(c, { ev: e1.id, club: I.demoKlubi[0], user: kupec, quantity: 2, pi: "test_" + crypto.randomUUID(), promo: promoDemo.id });
  const nSandbox = await narocilo(c, { ev: e1.id, club: I.demoKlubi[0], user: kupec, pi: "pi_sandbox1", seja: "cs_test_abc", acct: "acct_demo", fee: 150 });
  const nVip = await narocilo(c, { ev: e1.id, club: I.demoKlubi[0], user: kupec, unit: 30000, pi: "test_" + crypto.randomUUID(), tableId: miza1.id, tableLabel: "D1", tableSeats: 6, packageId: paket1.id, packageName: "Jameson" });
  const nGost = await narocilo(c, { ev: e1.id, club: I.demoKlubi[0], pi: "test_" + crypto.randomUUID(), guest: true, email: "gost@example.com" });
  const nFailed = await narocilo(c, { ev: e1.id, club: I.demoKlubi[0], user: kupec, status: "failed", pi: "pi_realfailed", seja: "cs_live_dead1" });
  const nCancelled = await narocilo(c, { ev: e1.id, club: I.demoKlubi[0], user: kupec, status: "cancelled", seja: "cs_live_dead2" });
  const nVracilo = await narocilo(c, { ev: e1o.id, club: I.demoKlubi[0], user: kupec, status: "refunded", pi: "test_" + crypto.randomUUID(), refunded: 1500 });
  const tLazni = [await vstopnica(c, nLazni.id, e1.id), await vstopnica(c, nLazni.id, e1.id, "used")];
  const tSandbox = await vstopnica(c, nSandbox.id, e1.id);
  const tVip = await vstopnica(c, nVip.id, e1.id);
  const tGost = await ins(c, "tickets", { order_id: nGost.id, event_id: e1.id, holder_is_guest: true, holder_guest_email: "gost@example.com" });
  await ins(c, "ticket_transfers", { ticket_id: tSandbox.id, from_user_id: kupec, to_user_id: kupec2, to_email: "kupec2@example.com", old_serial: crypto.randomUUID(), new_serial: crypto.randomUUID() });
  await ins(c, "gost_zetoni", { token_hash: hex(1), order_id: nGost.id });
  await ins(c, "gost_zetoni_vstopnic", { token_hash: hex(2), ticket_id: tGost.id });
  await ins(c, "table_service", { event_id: e1.id, order_id: nVip.id, club_id: I.demoKlubi[0], table_label: "D1", table_seats: 6, scanned_at: new Date() });
  const glDemo = await ins(c, "guest_lists", { event_id: e1.id, host_user_id: kupec, spots: 5, created_by: admin });
  const nGl = await narocilo(c, { ev: e1.id, club: I.demoKlubi[0], user: kupec, unit: 0, guestListId: glDemo.id });
  const tGl = await vstopnica(c, nGl.id, e1.id);
  await ins(c, "guest_list_members", { guest_list_id: glDemo.id, user_id: kupec, ticket_id: tGl.id });
  await ins(c, "vracila", { order_id: nVracilo.id, event_id: e1o.id, razlog: "event_cancelled", stanje: "opravljeno", znesek_cents: 1500, brez_stripa: true });
  I.demoNarocila = [nLazni, nSandbox, nVip, nGost, nFailed, nCancelled, nVracilo, nGl].map((x) => x.id);
  I.demoVstopnice = [...tLazni, tSandbox, tVip, tGost, tGl].map((x) => x.id);
  I.nLazni = nLazni.id; I.nSandbox = nSandbox.id;
  // Narocila se vsaj na enem dogodku vsakega drugega demo kluba (testni promet).
  for (let i = 1; i < 5; i++) {
    const n = await narocilo(c, { ev: dem[i].p.id, club: I.demoKlubi[i], user: kupec, pi: "test_" + crypto.randomUUID() });
    await vstopnica(c, n.id, dem[i].p.id);
  }

  // --- demo: prijave, predlog agenta, prosnja ustvarjalca, dnevnik
  await ins(c, "reports", { reporter_id: kupec, target_type: "club", target_id: I.demoKlubi[0], reason: "spam" });
  await ins(c, "reports", { reporter_id: kupec, target_type: "event", target_id: e1.id, reason: "spam" });
  await ins(c, "reports", { reporter_id: kupec, target_type: "user", target_id: kupec2, reason: "spam" });
  await ins(c, "reports", { reporter_id: kupec, target_type: "club", target_id: outly.id, reason: "spam" });
  const zetonAgenta = await ins(c, "agent_zetoni", { ime: "test", zeton_sha256: hex(3), obseg: ["beri", "predlagaj"], velja_do: new Date(Date.now() + 864e5) });
  const predlog = (cilj, id, stanje = "caka") => ins(c, "predlogi_dejanj", { agent_zeton_id: zetonAgenta.id, dejanje: "event.ustavi_prodajo", cilj_tip: cilj, cilj_id: id, spremembe: {}, razlog: "test", stanje,
    ...(stanje === "caka" ? {} : { odloceno_at: new Date() }) });
  I.predlogi = { demoCaka: (await predlog("event", e1.id)).id, demoKlubCaka: (await predlog("club", I.demoKlubi[1])).id, demoPotrjen: (await predlog("event", e1.id, "potrjen")).id };
  const app = await ins(c, "creator_applications", { user_id: lastnikiDemo[0], business_name: "Velvet d.o.o.", contact_name: "Janez Novak", email: "velvet@example.com", status: "approved", decided_at: new Date(), club_id: I.demoKlubi[0] });
  I.prosnja = app.id;
  await ins(c, "admin_dejanja", { admin_user_id: admin, dejanje: "club.uredi", cilj_tip: "club", cilj_id: String(I.demoKlubi[0]) });

  // --- Outly: QUICKIE (objavljen, prihodnji), Launch Party (odpovedan); PRAVA narocila, racun, spor, Stripovo vracilo, VIP, guest lista, promo koda
  const quickie = await dogodek(c, outly.id, "QUICKIE - For the first time", 14, "published", { capacity: 300 });
  const launch = await dogodek(c, outly.id, "Outly Launch Party", 3, "cancelled", { vip_layout_from_club_id: null });
  I.quickie = quickie.id; I.launch = launch.id;
  const miza = await ins(c, "club_tables", { club_id: outly.id, label: "O1", x: 1, y: 1, w: 2, h: 2, seats: 8, price_cents: 40000 });
  const paket = await ins(c, "bottle_packages", { club_id: outly.id, name: "Grey Goose", description: "pravi" });
  await ins(c, "event_tables", { event_id: quickie.id, table_id: miza.id });
  const promo = await ins(c, "promo_codes", { code: "OUTLYPROMO", label: "Max", club_id: outly.id, created_by: admin });
  await ins(c, "promo_code_events", { promo_code_id: promo.id, event_id: quickie.id });
  const r1 = await narocilo(c, { ev: quickie.id, club: outly.id, user: kupec, quantity: 2, pi: "pi_live1", seja: "cs_live_1", acct: "acct_outly", fee: 0 });
  const r2 = await narocilo(c, { ev: quickie.id, club: outly.id, user: kupec2, pi: "pi_live2", seja: "cs_live_2", acct: "acct_outly", promo: promo.id });
  const r3 = await narocilo(c, { ev: quickie.id, club: outly.id, user: kupec, pi: "test_" + crypto.randomUUID() });
  const r4 = await narocilo(c, { ev: quickie.id, club: outly.id, user: kupec, unit: 40000, pi: "pi_live4", seja: "cs_live_4", tableId: miza.id, tableLabel: "O1", tableSeats: 8, packageId: paket.id, packageName: "Grey Goose" });
  const r5 = await narocilo(c, { ev: launch.id, club: outly.id, user: kupec2, status: "refunded", pi: "pi_live5", seja: "cs_live_5", refunded: 1500 });
  const tr = [await vstopnica(c, r1.id, quickie.id), await vstopnica(c, r1.id, quickie.id, "used"), await vstopnica(c, r2.id, quickie.id), await vstopnica(c, r3.id, quickie.id), await vstopnica(c, r4.id, quickie.id)];
  await ins(c, "ticket_transfers", { ticket_id: tr[2].id, from_user_id: kupec2, to_user_id: kupec, to_email: "kupec@example.com", old_serial: crypto.randomUUID(), new_serial: crypto.randomUUID() });
  await ins(c, "table_service", { event_id: quickie.id, order_id: r4.id, club_id: outly.id, table_label: "O1", table_seats: 8, scanned_at: new Date() });
  const glO = await ins(c, "guest_lists", { event_id: quickie.id, host_user_id: kupec, spots: 3, created_by: admin });
  const nGlO = await narocilo(c, { ev: quickie.id, club: outly.id, user: kupec, unit: 0, guestListId: glO.id });
  const tGlO = await vstopnica(c, nGlO.id, quickie.id);
  await ins(c, "guest_list_members", { guest_list_id: glO.id, user_id: kupec, ticket_id: tGlO.id });
  await ins(c, "racuni", { order_id: r1.id, vrsta: "racun", znesek_cents: 3000 });
  await ins(c, "spori", { id: "dp_test1", order_id: r1.id, stanje: "odprt" });
  await ins(c, "vracila", { order_id: r5.id, event_id: launch.id, razlog: "event_cancelled", stanje: "opravljeno", znesek_cents: 1500, stripe_vracilo_id: "re_test1" });
  await ins(c, "vracila_iz_stripa", { vracilo_id: "re_test2", charge_id: "ch_test1", order_id: r5.id, znesek_cents: 1500, skupaj_vrnjeno_cents: 1500 });
  await ins(c, "view_counts", { club_id: outly.id, event_id: quickie.id, day: "2026-10-20", count: 40 });
  await ins(c, "event_favorites", { user_id: kupec, event_id: quickie.id });
  await ins(c, "event_interest", { user_id: kupec2, event_id: quickie.id });
  await ins(c, "club_event_notifications", { user_id: kupec, event_id: quickie.id });
  await ins(c, "gost_zetoni", { token_hash: hex(4), order_id: r2.id });
  await ins(c, "gost_zetoni_vstopnic", { token_hash: hex(5), ticket_id: tr[3].id });
  await ins(c, "table_holds", { event_id: quickie.id, table_id: miza.id, guest_name: "Rezervirano" });
  I.predlogi.outlyCaka = (await predlog("event", quickie.id)).id;
  I.outlyNarocila = [r1, r2, r3, r4, r5, nGlO].map((x) => x.id);
  I.r1 = r1.id; I.r3 = r3.id;
  return I;
}

// ---------------------------------------------------------------- posnetek tistega, kar mora ostati
// $1 demo klubi, $2 demo dogodki, $3 demo narocila, $4 prosnje ustvarjalcev z demo klubom.
// Seznami id-jev so celi stevili iz naseh vstavkov, zato jih vstavimo kot literale (pg zavrne parametre, ki jih poizvedba ne uporablja).
const lit = (a, tip) => `'{${a.join(",")}}'::${tip}[]`;
const posnetekTabele = (par) => {
  const K = lit(par[0], "int"), E = lit(par[1], "int"), O = lit(par[2], "bigint"), A = lit(par[3], "int");
  return {
  clubs: `clubs WHERE id <> ALL(${K})`,
  events: `events WHERE id <> ALL(${E})`,
  orders: `orders WHERE id <> ALL(${O})`,
  tickets: `tickets WHERE event_id <> ALL(${E})`,
  ticket_transfers: `ticket_transfers WHERE ticket_id IN (SELECT id FROM tickets WHERE event_id <> ALL(${E}))`,
  guest_lists: `guest_lists WHERE event_id <> ALL(${E})`,
  guest_list_members: `guest_list_members WHERE guest_list_id IN (SELECT id FROM guest_lists WHERE event_id <> ALL(${E}))`,
  gost_zetoni: `gost_zetoni WHERE order_id <> ALL(${O})`,
  gost_zetoni_vstopnic: `gost_zetoni_vstopnic WHERE ticket_id IN (SELECT id FROM tickets WHERE event_id <> ALL(${E}))`,
  club_tables: `club_tables WHERE club_id <> ALL(${K})`,
  event_tables: `event_tables WHERE event_id <> ALL(${E})`,
  bottle_packages: `bottle_packages WHERE club_id <> ALL(${K})`,
  table_service: `table_service WHERE club_id <> ALL(${K})`,
  table_holds: `table_holds WHERE event_id <> ALL(${E})`,
  vracila: `vracila WHERE event_id <> ALL(${E})`,
  vracila_iz_stripa: `vracila_iz_stripa WHERE order_id <> ALL(${O})`,
  racuni: `racuni WHERE order_id <> ALL(${O})`,
  spori: `spori WHERE order_id IS NULL OR order_id <> ALL(${O})`,
  promo_codes: `promo_codes WHERE club_id IS NULL OR club_id <> ALL(${K})`,
  promo_code_events: `promo_code_events WHERE event_id <> ALL(${E})`,
  view_counts: `view_counts WHERE club_id <> ALL(${K})`,
  club_follows: `club_follows WHERE club_id <> ALL(${K})`,
  club_members: `club_members WHERE club_id <> ALL(${K})`,
  club_invites: `club_invites WHERE club_id <> ALL(${K})`,
  event_favorites: `event_favorites WHERE event_id <> ALL(${E})`,
  event_interest: `event_interest WHERE event_id <> ALL(${E})`,
  club_event_notifications: `club_event_notifications WHERE event_id <> ALL(${E})`,
  odpovedi_dogodkov: `odpovedi_dogodkov WHERE event_id <> ALL(${E})`,
  users: `users`,
  admin_dejanja: `admin_dejanja`,
  agent_zetoni: `agent_zetoni`,
  reports: `reports WHERE NOT (target_type IN ('club', 'media') AND target_id = ANY(${K})) AND NOT (target_type = 'event' AND target_id = ANY(${E}))`,
  predlogi_dejanj: `predlogi_dejanj WHERE NOT (cilj_tip = 'event' AND cilj_id = ANY(${E})) AND NOT (cilj_tip = 'club' AND cilj_id = ANY(${K}))`,
  creator_applications: `creator_applications WHERE id <> ALL(${A})`,
  };
};
// Tabele, kjer po brisanju ne sme ostati NOBENA druga vrstica kot tiste iz posnetka (vse demo je izginilo).
const SAMO_OSTANKI = Object.keys(posnetekTabele([[], [], [], []])).filter((t) => !["reports", "predlogi_dejanj", "creator_applications"].includes(t));
async function parametri(c, I) {
  const naroc = (await c.query("SELECT COALESCE(array_agg(id), '{}') AS a FROM orders WHERE event_id = ANY($1::int[])", [I.demoDogodki])).rows[0].a;
  return [I.demoKlubi, I.demoDogodki, naroc, [I.prosnja]];
}
async function posnetek(c, par) {
  const izid = {};
  for (const [t, kje] of Object.entries(posnetekTabele(par))) {
    const r = await c.query(`SELECT COUNT(*)::int AS n, md5(COALESCE(string_agg(x.j, '|' ORDER BY x.j), '')) AS h FROM (SELECT to_jsonb(t)::text AS j FROM ${kje.replace(/^(\w+)/, "$1 t")}) x`);
    izid[t] = r.rows[0];
  }
  return izid;
}
const skupno = async (c) => (await c.query(`SELECT (SELECT COUNT(*) FROM clubs) AS k, (SELECT COUNT(*) FROM events) AS e, (SELECT COUNT(*) FROM orders) AS o, (SELECT COUNT(*) FROM tickets) AS t,
  (SELECT COUNT(*) FROM guest_lists) AS g, (SELECT COUNT(*) FROM vracila) AS v, (SELECT COUNT(*) FROM reports) AS r, (SELECT COUNT(*) FROM predlogi_dejanj WHERE stanje = 'caka') AS p`)).rows[0];

// Zazene 066 v transakciji, ki se vrne nazaj. Vrne { napaka?, obvestila }.
async function poskusi(c, pripravi) {
  const obvestila = [];
  const naNotice = (n) => obvestila.push(n.message);
  c.on("notice", naNotice);
  let napaka = null;
  await c.query("BEGIN");
  try { if (pripravi) await pripravi(); await c.query(SQL066); } catch (e) { napaka = e; }
  const znotraj = napaka ? null : await skupno(c);
  const e2 = napaka ? null : (await c.query("SELECT COUNT(*)::int AS n FROM clubs WHERE is_demo")).rows[0].n;
  await c.query("ROLLBACK");
  c.off("notice", naNotice);
  return { napaka, obvestila, znotraj, demoPo: e2 };
}

(async () => {
  const vzd = await odjemalec(vzdUrl);
  let c = null, srv = null, log = "";
  const pocisti = async () => {
    if (srv) srv.kill();
    try { jwksServer.close(); } catch (_) {}
    if (c) await c.end().catch(() => {});
    await vzd.query(`DROP DATABASE IF EXISTS ${IME_BAZE} WITH (FORCE)`).catch(() => {});
    await vzd.query(`DROP DATABASE IF EXISTS ${IME_PRAZNE} WITH (FORCE)`).catch(() => {});
    await vzd.end().catch(() => {});
  };
  try {
    console.log(`\n# Priprava: sveza baza ${IME_BAZE}, migracije do 065, podatki, ki posnemajo produkcijo`);
    await vzd.query(`CREATE DATABASE ${IME_BAZE}`);
    const m0 = migrate(urlBaze(IME_BAZE), ["--do", "065"]);
    assert(m0.koda === 0 && /065_promo_kode\.sql \.\.\. v redu/.test(m0.izpis) && /ustavljam se pred 066/.test(m0.izpis), "migrate.js --do 065 -> 0, 066 se ni uporabljena", m0.izpis.slice(-300));
    c = await odjemalec(urlBaze(IME_BAZE));
    const I = await podatki(c);
    const par = await parametri(c, I);
    const pred = await posnetek(c, par);
    const predSkupno = await skupno(c);
    assert(predSkupno.k == 7 && predSkupno.e == 17 && (await c.query("SELECT COUNT(*)::int AS n FROM clubs WHERE is_demo")).rows[0].n === 5,
      "pred migracijo: 7 klubov (5 demo), 17 dogodkov", predSkupno);
    assert(pred.orders.n >= 6 && pred.racuni.n === 1 && pred.spori.n === 1 && pred.vracila_iz_stripa.n === 1 && pred.vracila.n === 1 && pred.guest_lists.n === 1,
      "Outly ima prava narocila, racun, spor, Stripovo vracilo in guest listo", { orders: pred.orders.n });

    // ------------------------------------------------------------ varovala (vsako v svoji transakciji, ki se razveljavi)
    console.log("\n# 1. Varovala: migracija pade, nic se ne izbrise");
    const zanikaj = async (ime, pripravi, vzorec) => {
      const r = await poskusi(c, pripravi);
      assert(r.napaka && vzorec.test(r.napaka.message), `varovalo: ${ime}`, r.napaka ? r.napaka.message.slice(0, 200) : "migracija je uspela");
      const po = await skupno(c);
      assert(JSON.stringify(po) === JSON.stringify(predSkupno), `  po padcu ni sprememb (${ime})`, [po, predSkupno]);
    };
    const prvaDemoPrihodnja = I.demo[0].f.id;
    await zanikaj("(a) pravo placano narocilo na demo dogodku", () => narocilo(c, { ev: prvaDemoPrihodnja, club: I.demoKlubi[0], user: I.kupec, pi: "pi_resnicno", seja: "cs_live_resnicno" }), /pravih \(ne testnih\) narocil/);
    await zanikaj("(a) pravo narocilo v obdelavi (pending) na demo dogodku", () => narocilo(c, { ev: prvaDemoPrihodnja, club: I.demoKlubi[0], user: I.kupec, status: "pending", seja: "cs_live_cakajoce" }), /pravih \(ne testnih\) narocil/);
    await zanikaj("(a) pravo narocilo brez Stripa (0 EUR) na demo dogodku", () => narocilo(c, { ev: prvaDemoPrihodnja, club: I.demoKlubi[0], user: I.kupec, unit: 0 }), /pravih \(ne testnih\) narocil/);
    await zanikaj("(a) pravo v celoti vrnjeno narocilo", () => narocilo(c, { ev: prvaDemoPrihodnja, club: I.demoKlubi[0], user: I.kupec, status: "refunded", pi: "pi_vrnjeno", seja: "cs_live_vrnjeno", refunded: 1500 }), /pravih \(ne testnih\) narocil/);
    await zanikaj("(b) davcni racun za testno narocilo demo dogodka", () => c.query("INSERT INTO racuni (order_id, vrsta, znesek_cents) VALUES ($1, 'racun', 3000)", [I.nLazni]), /davcnih racunov/);
    await zanikaj("(b) spor za narocilo demo dogodka", () => c.query("INSERT INTO spori (id, order_id, stanje) VALUES ('dp_demo', $1, 'odprt')", [I.nSandbox]), /sporov/);
    await zanikaj("(b) Stripovo vracilo (vracila_iz_stripa) za narocilo demo dogodka", () => c.query("INSERT INTO vracila_iz_stripa (vracilo_id, charge_id, order_id, znesek_cents, skupaj_vrnjeno_cents) VALUES ('re_demo', 'ch_demo', $1, 100, 100)", [I.nSandbox]), /Stripovih vracil/);
    await zanikaj("(b) vracilo z oznako Stripa na demo dogodku", () => c.query("UPDATE vracila SET stripe_vracilo_id = 're_demo2' WHERE event_id = ANY($1::int[])", [I.demoDogodki]), /vracil z oznako Stripa/);
    await zanikaj("(c) demo klub z imenom Outly", () => c.query("UPDATE clubs SET name = ' outly ' WHERE id = $1", [I.demoKlubi[2]]), /»Outly« ali uradni profil/);
    await zanikaj("(c) demo klub je uradni profil", () => c.query("UPDATE clubs SET is_official = TRUE WHERE id = $1", [I.demoKlubi[3]]), /»Outly« ali uradni profil/);
    await zanikaj("(c) narocilo demo kluba na dogodku, ki ostane", () => narocilo(c, { ev: I.quickie, club: I.demoKlubi[0], user: I.kupec, pi: "test_" + crypto.randomUUID() }), /club_id demo kluba na dogodku, ki ostane/);
    await zanikaj("(c) Outly narocilo kaze na mizo demo kluba", () => narocilo(c, { ev: I.quickie, club: I.outly, user: I.kupec, unit: 30000, pi: "test_" + crypto.randomUUID(), tableId: I.demoMiza, tableLabel: "D1", tableSeats: 6 }), /mizo\/paket\/kodo\/guest listo/);
    await zanikaj("(c) Outly narocilo kaze na paket demo kluba", () => narocilo(c, { ev: I.quickie, club: I.outly, user: I.kupec, pi: "test_" + crypto.randomUUID(), packageId: I.demoPaket, packageName: "Jameson" }), /mizo\/paket\/kodo\/guest listo/);
    await zanikaj("(c) Outly narocilo uporablja promo kodo demo kluba", () => c.query("UPDATE orders SET promo_code_id = (SELECT id FROM promo_codes WHERE code = 'DEMOPROMO') WHERE id = $1", [I.r3]), /mizo\/paket\/kodo\/guest listo/);
    await zanikaj("(c) neodpovedan Outly dogodek ima demo klub za prizorisce", () => c.query("UPDATE events SET venue_club_id = $1 WHERE id = $2", [I.demoKlubi[0], I.quickie]), /ima demo klub za prizorisce/);

    console.log("\n# 2. Dovoljeno: odpovedan dogodek drugega kluba z demo prizoriscem, vip_layout_from_club_id, pravo failed/cancelled narocilo");
    const dov = await poskusi(c, async () => {
      await c.query("UPDATE events SET venue_club_id = $1 WHERE id = $2", [I.demoKlubi[0], I.launch]);
      await c.query("UPDATE events SET vip_layout_from_club_id = $1 WHERE id = $2", [I.demoKlubi[1], I.quickie]);
    });
    assert(!dov.napaka && dov.demoPo === 0, "migracija uspe (odpovedan dogodek s prizoriscem, vip_layout_from_club_id; pravi failed/cancelled sta ze v podatkih)", dov.napaka && dov.napaka.message);
    assert(dov.obvestila.some((m) => /kaskada events tujih klubov \(venue_club_id\/vip_layout_from_club_id -> NULL\): 2/.test(m)), "dnevnik pove, da dva tuja dogodka izgubita kazalec na demo klub", dov.obvestila.filter((m) => /tujih/.test(m)));

    // ------------------------------------------------------------ pravi zagon prek migrate.js
    console.log("\n# 3. Pravi zagon: db/migrate.js uporabi 066");
    const mig = migrate(urlBaze(IME_BAZE));
    assert(mig.koda === 0 && /066_brisanje_demo_klubov\.sql \.\.\. v redu/.test(mig.izpis), "migrate.js -> 0, 066 v redu", mig.izpis.slice(-600));
    for (const vzorec of [/066: demo klubov 5, dogodkov 15, narocil 12, vstopnic \d+/, /066: orders 12 \(od tega guest lista 1\)/, /066: tickets \d+/, /066: clubs 5/, /066: events 15/,
      /066: predlogi_dejanj poteceni 2/, /066: reports 2/, /uporabniki brez kluba po brisanju \(niso izbrisani\): \{/, /066: ostal klub id=\d+ ime=Outly/]) {
      assert(vzorec.test(mig.izpis), `dnevnik deploya vsebuje ${vzorec}`, mig.izpis.slice(-1500));
    }
    const zapis = (await c.query("SELECT odtis FROM schema_migrations WHERE datoteka = '066_brisanje_demo_klubov.sql'")).rows;
    const odtis = crypto.createHash("sha256").update(fs.readFileSync(path.join(KOREN, "db", "migracije", "066_brisanje_demo_klubov.sql"), "utf8")).digest("hex").slice(0, 16);
    assert(zapis.length === 1 && zapis[0].odtis === odtis, "v schema_migrations je 066 z odtisom datoteke", zapis);
    const vse = fs.readFileSync(path.join(KOREN, "db", "VSE_MIGRACIJE.sql"), "utf8");
    assert(vse.includes(`('066_brisanje_demo_klubov.sql', '${odtis}')`), "odtis je dopisan v db/VSE_MIGRACIJE.sql", odtis);
    const brez = fs.readFileSync(path.join(KOREN, "db", "migracije", "066_brisanje_demo_klubov.sql"), "utf8").split("\n").filter((v) => !/^\s*(BEGIN|COMMIT)\s*;\s*$/i.test(v)).join("\n").replace(/^\n+|\n+$/g, "");
    assert(vse.includes("\n" + brez + "\n"), "blok 066 v db/VSE_MIGRACIJE.sql je enak datoteki (brez BEGIN/COMMIT)");

    console.log("\n# 4. Po brisanju: demo je izginilo, vse ostalo je bit-za-bitom enako");
    const po = await posnetek(c, par);
    for (const t of Object.keys(pred)) assert(po[t].n === pred[t].n && po[t].h === pred[t].h, `${t}: ${pred[t].n} vrstic, md5 enak`, { pred: pred[t], po: po[t] });
    for (const t of SAMO_OSTANKI) {
      const n = (await c.query(`SELECT COUNT(*)::int AS n FROM ${t}`)).rows[0].n;
      assert(n === pred[t].n, `${t}: nobena demo vrstica ni ostala (skupaj ${n} = ostanek ${pred[t].n})`, n);
    }
    const klubiPo = (await c.query("SELECT id, name FROM clubs ORDER BY id")).rows;
    assert(klubiPo.length === 2 && klubiPo[0].name === "Outly" && klubiPo[1].name === "Stari pravi klub", "klubi: samo Outly in stari pravi klub", klubiPo);
    assert((await c.query("SELECT COUNT(*)::int AS n FROM clubs WHERE is_demo")).rows[0].n === 0, "noben klub ni vec is_demo");
    const dogPo = (await c.query("SELECT title FROM events ORDER BY id")).rows.map((r) => r.title);
    assert(dogPo.join("|") === "QUICKIE - For the first time|Outly Launch Party", "dogodki: samo QUICKIE in Launch Party", dogPo);
    const q = (await c.query("SELECT status, sold_count, vip_enabled, ticket_price_cents, venue_club_id FROM events WHERE id = $1", [I.quickie])).rows[0];
    assert(q.status === "published" && q.sold_count === 4 && q.vip_enabled && q.ticket_price_cents === 1500 && q.venue_club_id === null, "QUICKIE: objavljen, sold_count 4, VIP, cena 15 EUR", q);
    const pr = (await c.query("SELECT id, stanje, napaka FROM predlogi_dejanj ORDER BY id")).rows;
    const ps = Object.fromEntries(pr.map((p) => [p.id, p]));
    assert(ps[I.predlogi.demoCaka].stanje === "potekel" && ps[I.predlogi.demoKlubCaka].stanje === "potekel" && /izbrisan/.test(ps[I.predlogi.demoCaka].napaka), "odprta predloga za izbrisani dogodek/klub sta potekla", pr);
    assert(ps[I.predlogi.outlyCaka].stanje === "caka" && ps[I.predlogi.demoPotrjen].stanje === "potrjen", "predlog za Outly caka naprej, odlocen predlog ostane zgodovina", pr);
    const pro = (await c.query("SELECT club_id, status FROM creator_applications WHERE id = $1", [I.prosnja])).rows[0];
    assert(pro && pro.club_id === null && pro.status === "approved", "prosnja ustvarjalca ostane (club_id NULL)", pro);
    const rep = (await c.query("SELECT target_type FROM reports ORDER BY id")).rows.map((r) => r.target_type);
    assert(rep.join() === "user,club", "prijave: ostaneta samo user in Outly klub", rep);
    const lastniki = (await c.query(`SELECT u.email, EXISTS (SELECT 1 FROM clubs k WHERE k.owner_user_id = u.id) OR EXISTS (SELECT 1 FROM club_members m WHERE m.user_id = u.id) AS ima_klub
      FROM users u ORDER BY u.id`)).rows;
    assert(lastniki.length === pred.users.n && pred.users.n >= 12, `uporabniki: vseh ${pred.users.n} je ostalo (nihce ni izbrisan)`, lastniki.length);
    const brezKluba = lastniki.filter((u) => !u.ima_klub).map((u) => u.email).sort();
    assert(brezKluba.includes("clan.demo@example.com") && brezKluba.filter((e) => e.startsWith("lastnik.") && !/outly|stari/.test(e)).length === 5 && !brezKluba.includes("clan.obe@example.com"),
      "brez kluba ostanejo lastniki demo klubov in clan samo demo kluba; clan Outlyja ostane clan", brezKluba);

    console.log("\n# 5. Ponovni zagon ne naredi nicesar");
    const znova = await poskusi(c);
    assert(!znova.napaka && znova.obvestila.some((m) => /ni demo klubov, nic za brisanje/.test(m)), "066 brez demo klubov: obvestilo in nobene napake", znova.napaka && znova.napaka.message);
    const po2 = await posnetek(c, par);
    assert(Object.keys(pred).every((t) => po2[t].h === po[t].h && po2[t].n === po[t].n), "po ponovnem zagonu je vse enako");
    const mig2 = migrate(urlBaze(IME_BAZE));
    assert(mig2.koda === 0 && /Baza je usklajena/.test(mig2.izpis), "migrate.js drugic: baza je usklajena", mig2.izpis.slice(-200));

    // ------------------------------------------------------------ API po brisanju
    console.log("\n# 6. Javni API in GET /me po brisanju");
    await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
    srv = spawn("node", ["index.js"], { env: { ...process.env, DATABASE_URL: urlBaze(IME_BAZE).toString(), PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, cwd: KOREN, stdio: ["ignore", "pipe", "pipe"] });
    srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
    for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
    let r = await api("/clubs");
    const imena = (Array.isArray(r.body) ? r.body : r.body.clubs || []).map((k) => k.name).sort();
    assert(r.status === 200 && imena.join() === "Outly,Stari pravi klub", "GET /clubs -> 200: Outly in stari klub", [r.status, imena]);
    r = await api("/events");
    const naslovi = (Array.isArray(r.body) ? r.body : r.body.events || []).map((e) => e.title);
    assert(r.status === 200 && naslovi.includes("QUICKIE - For the first time") && !naslovi.some((t) => /Velvet|Nexus|Mirage|Mansion|Olie/.test(t)), "GET /events -> 200: QUICKIE je, demo dogodkov ni", naslovi);
    r = await api(`/events/${I.quickie}`);
    assert(r.status === 200 && r.body.title === "QUICKIE - For the first time" && r.body.is_demo === false, "GET /events/:id QUICKIE -> 200, is_demo false", [r.status, r.body.is_demo]);
    r = await api(`/events/${I.demoDogodki[0]}`);
    assert(r.status === 404, "GET /events/:id izbrisanega demo dogodka -> 404", r.status);
    r = await api(`/clubs/${I.demoKlubi[0]}`);
    assert(r.status === 404, "GET /clubs/:id izbrisanega demo kluba -> 404", r.status);
    r = await api(`/events/${I.quickie}/vip`);
    assert(r.status === 200 && r.body.enabled === true && r.body.tables.length === 1, "GET /events/:id/vip za QUICKIE -> 200 z mizo", [r.status, r.body.tables && r.body.tables.length]);
    r = await api("/me/invites");
    assert(r.status === 401, "GET /me/invites brez zetona -> 401", r.status);
    const tOutly = zeton("lastnik.outly@example.com", I.uporabniki["lastnik.outly@example.com"].uid);
    const tDemo = zeton("lastnik.velvet@example.com", I.uporabniki["lastnik.velvet@example.com"].uid);
    const tClan = zeton("clan.demo@example.com", I.uporabniki["clan.demo@example.com"].uid);
    r = await api("/me", tOutly);
    assert(r.status === 200 && r.body.club_id === I.outly && r.body.club_role === "owner" && r.body.clubs.length === 1, "GET /me lastnika Outlyja: klub in vloga owner", r.body);
    r = await api("/business/clubs/me", tOutly);
    assert(r.status === 200 && r.body.name === "Outly", "GET /business/clubs/me lastnika Outlyja -> 200", [r.status, r.body.name]);
    r = await api("/me", tDemo);
    assert(r.status === 200 && r.body.club_id === null && r.body.club_role === null && Array.isArray(r.body.clubs) && r.body.clubs.length === 0 && r.body.role === "business",
      "GET /me nekdanjega lastnika demo kluba -> 200 (vloga business, club_id null, clubs [])", r.body);
    r = await api("/business/clubs/me", tDemo);
    assert(r.status === 404, "GET /business/clubs/me nekdanjega lastnika demo kluba -> 404 Club not found (ne 500)", [r.status, r.body]);
    r = await api("/business/sales", tDemo);
    assert(r.status === 404, "GET /business/sales nekdanjega lastnika demo kluba -> 404 (ne 500)", [r.status, r.body]);
    r = await api("/me", tClan);
    assert(r.status === 200 && r.body.club_id === null && r.body.clubs.length === 0, "GET /me nekdanjega clana demo kluba -> 200 brez kluba", r.body);

    // ------------------------------------------------------------ prazna baza
    console.log("\n# 7. Prazna baza (sveza migracija): 066 ne naredi nicesar");
    await vzd.query(`CREATE DATABASE ${IME_PRAZNE}`);
    const polna = migrate(urlBaze(IME_PRAZNE));
    assert(polna.koda === 0 && /066_brisanje_demo_klubov\.sql \.\.\. v redu/.test(polna.izpis), "migrate.js na prazni bazi -> 0, 066 v redu", polna.izpis.slice(-300));
    assert(/066: ni demo klubov, nic za brisanje/.test(polna.izpis), "dnevnik: ni demo klubov", polna.izpis.slice(-600));
    const prazna = await odjemalec(urlBaze(IME_PRAZNE));
    const stPrazna = await skupno(prazna);
    await prazna.end();
    assert(Number(stPrazna.k) === 0 && Number(stPrazna.e) === 0, "prazna baza ostane prazna", stPrazna);
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
  } finally {
    await pocisti();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  if (fail) { console.log(log.slice(-2000)); process.exit(1); }
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
