// Headless preverjanje admin panela (24. 10. 2026): nov videz (kot aplikacija), navigacija brez emojijev, brez testnih prikazov, pravo brisanje dogodka/kluba/promo kode prek
// RESNICNEGA lokalnega backenda (svoja baza, JWKS stub; stubana je samo prijava pri Supabase). NI v `npm test` (rabi Playwright + Chromium, ki nista odvisnosti):
//   DATABASE_URL=postgres://postgres@localhost:5451/postgres NODE_PATH="$(npm root -g)" SHOTS=/pot/do/posnetkov node _testi/headless_admin_brisanje.js
// Sirine 1280 in 393; konzola brez napak (tudi pageerror); izhodna koda 1, ce kaj odpove. Backend na 6430, JWKS na 6431. TRUNCATE vseh tabel na zacetku.
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const { chromium } = require("playwright");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6430, JWKS_PORT = 6431, ORIGIN = `http://localhost:${PORT}`;
const SB = "https://zbewqcxnvrwebxonvebx.supabase.co";
const MAPA = process.env.SHOTS || ""; if (MAPA) fs.mkdirSync(MAPA, { recursive: true });
const KOREN = path.join(__dirname, "..");
let napake = 0;
const preveri = (ok, opis, podrobnost) => { console.log((ok ? "OK     " : "NAPAKA ") + opis + (ok ? "" : "  -> " + JSON.stringify(podrobnost))); if (!ok) napake++; };

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "headless-brisanje";
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
  const p = b64u({ iss: `http://127.0.0.1:${JWKS_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now, user_metadata: { email_verified: true, username: email.split("@")[0].replace(/[^a-z0-9_]/gi, "") } });
  return h + "." + p + "." + crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
}
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
function najdiChromium() {
  if (process.env.PW_CHROMIUM) return process.env.PW_CHROMIUM;
  const k = "/opt/pw-browsers";
  for (const m of (fs.existsSync(k) ? fs.readdirSync(k).filter((d) => /^chromium-\d+$/.test(d)).sort().reverse() : [])) { for (const pod of ["chrome-linux64", "chrome-linux"]) { const p = path.join(k, m, pod, "chrome"); if (fs.existsSync(p)) return p; } }
  throw new Error("Chromium ni najden (nastavi PW_CHROMIUM).");
}

async function ins(c, tab, o) {
  const k = Object.keys(o);
  return (await c.query(`INSERT INTO ${tab} (${k.join(",")}) VALUES (${k.map((x, i) => "$" + (i + 1)).join(",")}) RETURNING *`, k.map((x) => o[x]))).rows[0];
}
let stNar = 0;
async function narocilo(c, o) {
  stNar++;
  const q = o.quantity ?? 1, cena = o.unit ?? 1500, status = o.status ?? "paid";
  const n = await ins(c, "orders", { public_ref: `OUT-HL${String(stNar).padStart(4, "0")}`, user_id: o.user ?? null, event_id: o.ev, club_id: o.club, quantity: q, unit_price_cents: cena, total_cents: cena * q, status,
    buyer_email: o.email ?? "kupec@example.com", paid_at: o.dni !== undefined ? new Date(Date.now() - o.dni * 864e5) : new Date(), created_at: o.dni !== undefined ? new Date(Date.now() - o.dni * 864e5) : new Date(),
    stripe_payment_intent_id: o.pi ?? null, stripe_checkout_session_id: o.seja ?? null, stripe_account_id: o.acct ?? null, application_fee_cents: o.fee ?? 0, promo_code_id: o.promo ?? null });
  for (let i = 0; i < q; i++) await ins(c, "tickets", { order_id: n.id, event_id: o.ev, status: "valid" });
  return n;
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  const tabele = (await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name <> 'schema_migrations'")).rows.map((x) => `"${x.table_name}"`);
  await pool.query(`TRUNCATE ${tabele.join(", ")} RESTART IDENTITY CASCADE`);
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { cwd: KOREN, env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", TEST_PLACILA: "", VRACILA_TICK_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 80; i++) { try { await fetch(ORIGIN + "/"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
  const ADMIN = zeton("admin@outly.si", uuid(1));
  let brskalnik = null;
  try {
    brskalnik = await chromium.launch({ executablePath: najdiChromium(), args: ["--no-sandbox"] });
    // ---- podatki
    await fetch(ORIGIN + "/me", { headers: { authorization: "Bearer " + ADMIN } });
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    const mk = async (email, vloga = "user") => (await ins(pool, "users", { email, username: email.split("@")[0], role: vloga, email_verified: true, supabase_uid: crypto.randomUUID(), country: "SI" })).id;
    const adminId = (await pool.query("SELECT id FROM users WHERE email='admin@outly.si'")).rows[0].id;
    const lOutly = await mk("luka@outly.si", "business"), lTunel = await mk("tunel@primer.si", "business"), lCinema = await mk("cinema@primer.si", "business"), lDemo = await mk("demo@primer.si", "business");
    const kupci = []; for (let i = 1; i <= 6; i++) kupci.push(await mk(`kupec${i}@primer.si`));
    const outly = (await ins(pool, "clubs", { owner_user_id: lOutly, name: "Outly", city: "Ljubljana", is_organizer: true, is_official: true, genres: ["techno"] })).id;
    const tunel = (await ins(pool, "clubs", { owner_user_id: lTunel, name: "Klub Tunel", city: "Ljubljana", address: "Cesta 1", genres: ["house", "techno"], stripe_account_id: "acct_x", stripe_charges_enabled: true, stripe_payouts_enabled: true })).id;
    const cinema = (await ins(pool, "clubs", { owner_user_id: lCinema, name: "Cinema", city: "Maribor", genres: ["hip-hop"] })).id;
    const demo = (await ins(pool, "clubs", { owner_user_id: lDemo, name: "Klub za brisanje", city: "Celje", hidden: true })).id;
    const dan = 864e5, dogodek = (klub, naslov, pomik, status = "published", extra = {}) => ins(pool, "events", { club_id: klub, title: naslov, start_at: new Date(Date.now() + pomik * dan), status, ticket_price_cents: 1500, capacity: 300, genres: ["techno"], ...extra });
    const quickie = await dogodek(outly, "QUICKIE - For the first time", 3), nocoj = await dogodek(tunel, "Tunel Friday", 0.15, "published", { end_at: new Date(Date.now() + 0.6 * dan) });
    const landscape = await dogodek(tunel, "Landscape Party", 8), osnutek = await dogodek(cinema, "Osnutek: Halloween", 20, "draft"), odpov = await dogodek(cinema, "Odpovedan koncert", 5, "cancelled");
    const testni = await dogodek(demo, "Dogodek za brisanje", 12), testni2 = await dogodek(demo, "Klubski dogodek B", 14);
    for (let i = 0; i < 14; i++) { const ev = i % 3 === 0 ? nocoj : i % 3 === 1 ? quickie : landscape, kl = ev.club_id; await narocilo(pool, { ev: ev.id, club: kl, user: kupci[i % 6], quantity: 1 + (i % 3), dni: i % 9, pi: "pi_live" + i, seja: "cs_live_" + i, acct: "acct_x", fee: 75 }); }
    for (const ev of [testni, testni2]) { await narocilo(pool, { ev: ev.id, club: demo, user: kupci[0], pi: "test_" + crypto.randomUUID() }); await narocilo(pool, { ev: ev.id, club: demo, user: kupci[1], pi: "test_" + crypto.randomUUID(), quantity: 2 }); }
    const pMax = await ins(pool, "promo_codes", { code: "MAX12", label: "Max (promotor)", club_id: tunel, created_by: adminId });
    const pStara = await ins(pool, "promo_codes", { code: "STARA", label: "Stara akcija", club_id: cinema, created_by: adminId, active: false });
    await ins(pool, "promo_code_events", { promo_code_id: pStara.id, event_id: osnutek.id });
    await narocilo(pool, { ev: landscape.id, club: tunel, user: kupci[2], pi: "pi_livepromo1", seja: "cs_live_promo1", promo: pMax.id, dni: 1 });
    await narocilo(pool, { ev: landscape.id, club: tunel, user: kupci[3], pi: "pi_livepromo2", seja: "cs_live_promo2", promo: pMax.id, dni: 2 });
    await ins(pool, "club_members", { club_id: tunel, user_id: kupci[4], role: "doorman" });

    // ---- stub prijave (Supabase) + brskalnik
    const konzola = [];
    const novaStran = async (sirina, visina, mobilno) => {
      const ctx = await brskalnik.newContext({ viewport: { width: sirina, height: visina }, deviceScaleFactor: mobilno ? 2 : 1, isMobile: !!mobilno, hasTouch: !!mobilno, reducedMotion: "reduce" });
      await ctx.route(SB + "/**", async (route) => {
        const u = new URL(route.request().url());
        const json = (s, o) => route.fulfill({ status: s, contentType: "application/json", headers: { "access-control-allow-origin": "*" }, body: JSON.stringify(o) });
        if (route.request().method() === "OPTIONS") return route.fulfill({ status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-allow-methods": "*" } });
        if (u.pathname.endsWith("/token")) return json(200, { access_token: ADMIN, refresh_token: "R-1" });
        return json(404, {});
      });
      const page = await ctx.newPage();
      page.on("console", (m) => { if (m.type() === "error") konzola.push(`[${sirina}] console: ` + m.text()); });
      page.on("pageerror", (e) => konzola.push(`[${sirina}] pageerror: ` + e.message));
      const zahtevki = []; page.on("response", (r) => zahtevki.push([r.url(), r.status()]));
      page.__zahtevki = zahtevki;
      return page;
    };
    const posnetek = async (page, ime) => { if (MAPA) await page.screenshot({ path: path.join(MAPA, ime + ".png"), fullPage: false }); };
    const cakajDa = (page, f, arg) => page.waitForFunction(f, arg, { timeout: 8000 });
    const vpisi = async (page) => {
      await page.goto(ORIGIN + "/admin/");
      await page.fill("#pEmail", "admin@outly.si"); await page.fill("#pGeslo", "geslo"); await page.click("#pGumb");
      await cakajDa(page, () => !document.getElementById("panel").classList.contains("skrito"));
      await cakajDa(page, () => document.querySelectorAll("#dn_koren .stevilka").length > 0);
    };
    const EMOJI = /\p{Extended_Pictographic}|[\u2190-\u21FF\u2300-\u23FF\u25A0-\u27BF\u2B00-\u2BFF]/u;
    const NAV_ZNAKI = /[^\p{L}\p{N}\s.,:;()\-–'"/+&#!?%€]/u;   // karkoli razen crk, stevilk in navadnih locil (emoji, ◉ ▦ ≡ ☺ ...)
    const zavihek = async (page, z, mobilno) => {
      if (mobilno) {
        await page.evaluate((zz) => document.querySelector(`nav button[data-z="${zz}"]`).click(), z);
      } else await page.click(`nav button[data-z="${z}"]`);
    };
    const vodoravno = (page) => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);

    // ============================================================ RACUNALNIK 1280
    console.log("# Racunalnik 1280");
    const d = await novaStran(1280, 900, false);
    await vpisi(d);
    await posnetek(d, "01-pregled-danes-1280");
    const navBes = await d.evaluate(() => document.querySelector("nav").innerText);
    preveri(!NAV_ZNAKI.test(navBes), "navigacija (racunalnik) brez emojijev in simbolnih znakov", navBes);
    const pisava = await d.evaluate(async () => { await document.fonts.ready; return { inter: document.fonts.check("14px Inter"), fam: getComputedStyle(document.body).fontFamily, ozadje: getComputedStyle(document.body).backgroundColor }; });
    preveri(pisava.inter && /Inter/.test(pisava.fam) && pisava.ozadje === "rgb(17, 17, 17)", "pisava Inter z nase domene in ozadje #111111", pisava);
    preveri(d.__zahtevki.some(([u, s]) => /\/admin\/fonts\/inter-latin-wght-normal\.woff2$/.test(u) && s === 200), "pisava se nalozi z /admin/fonts/ (200), brez Google Fonts", d.__zahtevki.filter(([u]) => /font/i.test(u)));
    preveri(d.__zahtevki.every(([u]) => u.startsWith(ORIGIN) || u.startsWith(SB)), "panel ne nalaga nicesar z tujih domen", d.__zahtevki.filter(([u]) => !u.startsWith(ORIGIN) && !u.startsWith(SB)).map((x) => x[0]));
    const pregledBes = await d.evaluate(() => document.getElementById("z-pregled").innerText);
    preveri(!/testn|sandbox/i.test(pregledBes), "Pregled/Danes: brez testnih prikazov", pregledBes.slice(0, 400));
    preveri(await d.evaluate(() => document.getElementById("nacin_pas").classList.contains("skrito") === false && /niso v živem načinu/.test(document.getElementById("nacin_pas").innerText)), "backend ni v zivem nacinu: rdec pas »Placila niso v zivem nacinu«");
    await posnetek(d, "01b-rdec-pas-nacina-1280");
    // v zivem nacinu pasu ni (odgovor povozimo)
    await d.route(ORIGIN + "/admin/api/summary", async (route) => { const r = await route.fetch(); const j = await r.json(); j.payments_mode = "live"; await route.fulfill({ response: r, json: j }); });
    await d.click("nav button[data-z=pregled]"); await d.evaluate(() => window.naloziPregled());
    await cakajDa(d, () => document.getElementById("nacin_pas").classList.contains("skrito"));
    preveri(true, "v zivem nacinu rdecega pasu ni");
    await d.unroute(ORIGIN + "/admin/api/summary");

    await zavihek(d, "dogodki");
    await cakajDa(d, () => document.querySelectorAll("#dTabela tr.dg-vrstica").length >= 7);
    await posnetek(d, "02-dogodki-seznam-1280");
    // dogodek s pravim prometom: izbris ni mogoc, razlaga + Odpovej
    await d.click(`#dTabela tr.dg-vrstica:has-text("QUICKIE")`);
    await cakajDa(d, () => document.getElementById("dge_izbris_ni"));
    const razlaga = await d.evaluate(() => document.getElementById("dge_izbris_ni").innerText);
    preveri(/pravih naročil/.test(razlaga) && /Odpovej dogodek/.test(razlaga) && !(await d.$("#dge_izbrisi")), "dogodek s pravim prometom: namesto »Izbrisi« razlaga in »Odpovej dogodek«", razlaga);
    await posnetek(d, "03-dogodek-podrobnosti-s-prometom-1280");
    // dogodek brez pravega prometa: izbris prek dialoga
    await d.evaluate(() => { history.pushState(null, "", "#/dogodki"); });
    await d.click("nav button[data-z=pregled]"); await zavihek(d, "dogodki");
    await cakajDa(d, () => document.querySelectorAll("#dTabela tr.dg-vrstica").length >= 7);
    await d.click(`#dTabela tr.dg-vrstica:has-text("Dogodek za brisanje")`);
    await cakajDa(d, () => document.getElementById("dge_izbrisi"));
    await posnetek(d, "04-dogodek-podrobnosti-1280");
    await d.click("#dge_izbrisi");
    await cakajDa(d, () => document.querySelector(".dlg-okno.nevarno"));
    const okno = await d.evaluate(() => document.querySelector(".dlg-okno").innerText);
    preveri(/Izbrišem dogodek za vedno/.test(okno) && /4 naročil|3 naročil|naročil \(testnih/.test(okno) && /Za potrditev vpiši IZBRISI/.test(okno), "dialog brisanja dogodka: naslov, stevila, vpis IZBRISI", okno);
    preveri(await d.evaluate(() => document.querySelector(".dlg-gumbi button:last-child").disabled), "gumb »Izbrisi za vedno« je onemogocen, dokler ni vpisa in razloga");
    await posnetek(d, "05-dialog-brisanje-dogodka-1280");
    await d.fill(".dlg-okno input", "izbrisi"); await d.fill(".dlg-okno textarea", "Testni dogodek, ni vec potreben");
    await d.click(".dlg-gumbi button:last-child");
    await cakajDa(d, () => !document.querySelector(".dlg-okno"));
    await cakajDa(d, () => document.querySelectorAll("#dTabela tr.dg-vrstica").length === 6);
    preveri((await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE title='Dogodek za brisanje'")).rows[0].n === 0, "dogodek je dejansko izbrisan iz baze");
    preveri((await pool.query("SELECT COUNT(*)::int AS n FROM admin_dejanja WHERE dejanje='event.delete_hard' AND razlog='Testni dogodek, ni vec potreben'")).rows[0].n === 1, "dnevnik: event.delete_hard z razlogom");

    // Klubi
    await zavihek(d, "klubi");
    await cakajDa(d, () => document.querySelectorAll("#kTabela tbody tr").length === 4);
    await posnetek(d, "06-klubi-1280");
    const gumbiUradni = await d.evaluate(() => [...document.querySelectorAll("#kTabela tbody tr")].map((tr) => [tr.children[2].innerText.split("\n")[0], [...tr.querySelectorAll("button")].map((b) => b.textContent).join("|")]));
    preveri(gumbiUradni.find((x) => x[0] === "Outly") && !/Izbriši/.test(gumbiUradni.find((x) => x[0] === "Outly")[1]) && /Izbriši/.test(gumbiUradni.find((x) => x[0] === "Klub Tunel")[1]), "uradni profil nima gumba »Izbrisi«, ostali klubi ga imajo", gumbiUradni);
    await d.click(`#kTabela tbody tr:has-text("Klub za brisanje") button:has-text("Izbriši")`);
    await cakajDa(d, () => document.querySelector(".dlg-okno.nevarno"));
    const oknoK = await d.evaluate(() => document.querySelector(".dlg-okno").innerText);
    preveri(/Izbrišem klub za vedno/.test(oknoK) && /Klubski dogodek B/.test(oknoK) && /Uporabniki .* ostanejo/.test(oknoK), "dialog brisanja kluba: dogodki, uporabniki ostanejo", oknoK);
    await posnetek(d, "07-dialog-brisanje-kluba-1280");
    await d.fill(".dlg-okno input", "IZBRISI"); await d.fill(".dlg-okno textarea", "Testni klub");
    await d.click(".dlg-gumbi button:last-child");
    await cakajDa(d, () => document.querySelectorAll("#kTabela tbody tr").length === 3);
    preveri((await pool.query("SELECT (SELECT COUNT(*)::int FROM clubs WHERE name='Klub za brisanje') AS k, (SELECT COUNT(*)::int FROM events WHERE club_id=$1) AS e, (SELECT COUNT(*)::int FROM users WHERE email='demo@primer.si') AS u", [demo])).rows[0].k === 0, "klub izbrisan, uporabnik ostane");

    // Promo kode
    await zavihek(d, "promo");
    await cakajDa(d, () => document.querySelectorAll("#pk_koren .rc-kartica").length === 2);
    await posnetek(d, "08-promo-kode-1280");
    await d.click(`#pk_koren .rc-kartica:has-text("MAX12") button:has-text("Izbriši")`);
    await cakajDa(d, () => document.querySelector(".dlg-okno.nevarno"));
    const oknoP = await d.evaluate(() => document.querySelector(".dlg-okno").innerText);
    preveri(/uporabilo 2 naročil/.test(oknoP) && /Naročila in vstopnice ostanejo/.test(oknoP), "dialog brisanja promo kode: pokaze stevilo narocil, narocila ostanejo", oknoP);
    await posnetek(d, "09-dialog-brisanje-promo-1280");
    await d.fill(".dlg-okno input", "IZBRISI"); await d.fill(".dlg-okno textarea", "Akcija se je koncala");
    await d.click(".dlg-gumbi button:last-child");
    await cakajDa(d, () => document.querySelectorAll("#pk_koren .rc-kartica").length === 1);
    preveri((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [landscape.id])).rows[0].n >= 2 && (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE promo_code_id IS NOT NULL")).rows[0].n === 0, "narocila so ostala, promo_code_id je NULL");
    const promoBes = await d.evaluate(() => document.getElementById("z-promo").innerText);
    preveri(!/testn|sandbox/i.test(promoBes), "Promo kode: brez testnih prikazov");

    // Finance
    await zavihek(d, "finance");
    await cakajDa(d, () => document.querySelectorAll("#fKlubi tr").length > 1);
    await posnetek(d, "10-finance-1280");
    const finBes = await d.evaluate(() => document.getElementById("z-finance").innerText);
    preveri(!/testn|sandbox|\btest\b/i.test(finBes.replace(/NI V ŽIVEM NAČINU/g, "")), "Finance: brez testnega prometa (razen opozorila nacina)", finBes.slice(0, 300));
    preveri(!(await d.$("#fTestStevilke")), "Finance: razdelek »Testni promet« ne obstaja");
    for (const z of ["klubi", "uporabniki", "guest", "vracila", "pomoc", "agent", "predlogi", "opozorila", "prosnje", "prijave"]) {
      await zavihek(d, z); await d.waitForTimeout(250);
    }
    await zavihek(d, "uporabniki"); await d.waitForTimeout(300); await posnetek(d, "11-uporabniki-1280");
    await zavihek(d, "opozorila"); await d.waitForTimeout(400); await posnetek(d, "12-opozorila-1280");
    const pomocBes = await (async () => { await zavihek(d, "pomoc"); await d.waitForTimeout(200); return d.evaluate(() => document.getElementById("z-pomoc").innerText); })();
    preveri(!EMOJI.test(pomocBes), "zavihek Pomoc: brez emojijev", pomocBes);
    preveri(await vodoravno(d), "racunalnik: brez vodoravnega drsenja strani");

    // ============================================================ TELEFON 393
    console.log("# Telefon 393");
    const t = await novaStran(393, 852, true);
    await vpisi(t);
    await t.waitForTimeout(400);
    await posnetek(t, "20-pregled-danes-393");
    const barBes = await t.evaluate(() => document.getElementById("spodnja_vrstica").innerText);
    preveri(!NAV_ZNAKI.test(barBes), "spodnja vrstica (telefon) brez emojijev in simbolnih znakov", barBes);
    const ikone = await t.evaluate(() => [...document.querySelectorAll("#spodnja_vrstica .ikona")].map((e) => { const cs = getComputedStyle(e); return { w: e.offsetWidth, mask: (cs.webkitMaskImage || cs.maskImage || "").startsWith('url("data:image/svg+xml') }; }));
    preveri(ikone.length === 5 && ikone.every((i) => i.w === 24 && i.mask), "5 ikon v enem slogu (SVG maske, vgrajene v kodo)", ikone);
    preveri(await vodoravno(t), "telefon Pregled: brez vodoravnega drsenja");
    await t.click('#spodnja_vrstica button[data-t="vec"]');
    await cakajDa(t, () => !document.getElementById("lista").classList.contains("skrito"));
    await posnetek(t, "21-meni-vec-393");
    const listaBes = await t.evaluate(() => document.getElementById("lista").innerText);
    preveri(!NAV_ZNAKI.test(listaBes), "meni »Vec« brez emojijev", listaBes);
    await t.keyboard.press("Escape");
    await t.click('#spodnja_vrstica button[data-t="dogodki"]');
    await cakajDa(t, () => document.querySelectorAll("#dTabela tr.dg-vrstica").length >= 5);
    await posnetek(t, "22-dogodki-393");
    preveri(await vodoravno(t), "telefon Dogodki: brez vodoravnega drsenja");
    await t.click(`#dTabela tr.dg-vrstica:has-text("Landscape")`);
    await cakajDa(t, () => document.getElementById("dge_izbris_ni") || document.getElementById("dge_izbrisi"));
    await posnetek(t, "23-dogodek-podrobnosti-393");
    preveri(await vodoravno(t), "telefon podrobnosti dogodka: brez vodoravnega drsenja");
    // dialog brisanja na telefonu: dogodek brez prometa
    await t.evaluate(() => { history.pushState(null, "", "#/dogodki"); });
    await t.click('#spodnja_vrstica button[data-t="pregled"]'); await t.click('#spodnja_vrstica button[data-t="dogodki"]');
    await cakajDa(t, () => document.querySelectorAll("#dTabela tr.dg-vrstica").length >= 5);
    const ostalo = await t.evaluate(() => [...document.querySelectorAll("#dTabela tr.dg-vrstica")].map((r) => r.innerText.split("\n")[0]));
    console.log("  (dogodki na telefonu: " + ostalo.join(" | ") + ")");
    await t.click('#spodnja_vrstica button[data-t="vec"]'); await t.click('#lista button[data-z="promo"]');
    await cakajDa(t, () => document.querySelectorAll("#pk_koren .rc-kartica").length === 1);
    await posnetek(t, "24-promo-393");
    await t.click(`#pk_koren .rc-kartica button:has-text("Izbriši")`);
    await cakajDa(t, () => document.querySelector(".dlg-okno.nevarno"));
    await posnetek(t, "25-dialog-brisanje-393");
    preveri(await vodoravno(t), "telefon z odprtim dialogom: brez vodoravnega drsenja");
    await t.keyboard.press("Escape");
    await t.click('#spodnja_vrstica button[data-t="vec"]'); await t.click('#lista button[data-z="finance"]');
    await cakajDa(t, () => document.querySelectorAll("#fKlubi tr").length > 1);
    await posnetek(t, "26-finance-393");
    preveri(await vodoravno(t), "telefon Finance: brez vodoravnega drsenja (tabele drsijo v svoji vrstici)");
    await t.click('#spodnja_vrstica button[data-t="ljudje"]'); await t.click('#lista button[data-z="klubi"]');
    await cakajDa(t, () => document.querySelectorAll("#kTabela tbody tr").length === 3);
    await posnetek(t, "27-klubi-393");
    preveri(await vodoravno(t), "telefon Klubi: brez vodoravnega drsenja");

    preveri(konzola.length === 0, "konzola brez napak (console.error / pageerror)", konzola);
  } catch (e) {
    napake++; console.log("NAPAKA izjema: " + (e && e.stack || e));
  } finally {
    if (brskalnik) await brskalnik.close().catch(() => {});
    srv.kill(); jwksServer.close(); await pool.end().catch(() => {});
  }
  if (napake) console.log("\n--- backend ---\n" + log.slice(-2500));
  console.log(napake ? `\n${napake} napak` : "\nVse v redu");
  process.exit(napake ? 1 : 0);
})();
