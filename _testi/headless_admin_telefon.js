// Headless preverjanje admin panela na telefonu (#328, PR 10): spodnja vrstica 5 zavihkov, kartice v Klubih/Uporabnikih, brez vodoravnega drsenja,
// vsi zavihki dosegljivi, rdeci pas nujnih dejanj viden. Sirine 393, 360 (telefon) in 1280 (racunalnik). NI v `npm test` (rabi Playwright + Chromium, ki nista odvisnosti):
//   NODE_PATH="$(npm root -g)" SHOTS=/pot/do/posnetkov node _testi/headless_admin_telefon.js
// Stubana sta samo Supabase Auth in backend (kot headless_admin_seja.js); podatki so izmisljeni. Izhodna koda 1, ce kaj odpove.
const http = require("http");
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const SB = "https://zbewqcxnvrwebxonvebx.supabase.co";
const STRAN = fs.readFileSync(process.env.ADMIN_HTML || path.join(__dirname, "..", "admin", "index.html"));   // ADMIN_HTML: za preverbo, da test na stari kodi pade
let napake = 0;
function preveri(ok, opis, podrobnost) {
  console.log((ok ? "OK    " : "NAPAKA ") + opis + (ok ? "" : "  -> " + JSON.stringify(podrobnost)));
  if (!ok) napake++;
}

function najdiChromium() {
  if (process.env.PW_CHROMIUM) return process.env.PW_CHROMIUM;
  const korenina = "/opt/pw-browsers";
  const mape = fs.existsSync(korenina) ? fs.readdirSync(korenina).filter(d => /^chromium-\d+$/.test(d)).sort().reverse() : [];
  for (const m of mape) { const p = path.join(korenina, m, "chrome-linux", "chrome"); if (fs.existsSync(p)) return p; }
  throw new Error("Chromium ni najden (nastavi PW_CHROMIUM).");
}

// ---- stub Supabase Auth + backend ----
function novStub() {
  const st = { veljavniDostop: new Set(), veljavniRefresh: new Set(), stevec: 0, osvezitve: [], odjave: 0, nacinOsvezitve: "ok", priOsvezitvi: null, odgovori: {} };
  st.izdaj = () => {
    const n = ++st.stevec, o = { access_token: "A-" + n, refresh_token: "R-" + n };
    st.veljavniDostop.add(o.access_token); st.veljavniRefresh.add(o.refresh_token); return o;
  };
  return st;
}
async function namestiStub(ctx, st, origin) {
  await ctx.route(SB + "/**", async (route) => {
    const u = new URL(route.request().url());
    const telo = (() => { try { return JSON.parse(route.request().postData() || "{}"); } catch (_) { return {}; } })();
    const json = (status, o) => route.fulfill({ status, contentType: "application/json", headers: { "access-control-allow-origin": "*" }, body: JSON.stringify(o) });
    if (route.request().method() === "OPTIONS") return route.fulfill({ status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-allow-methods": "*" } });
    if (u.pathname.endsWith("/token") && u.searchParams.get("grant_type") === "password") {
      return telo.password === "geslo" ? json(200, st.izdaj()) : json(400, { error_description: "Invalid login credentials" });
    }
    if (u.pathname.endsWith("/token") && u.searchParams.get("grant_type") === "refresh_token") {
      st.osvezitve.push(telo.refresh_token);
      if (st.nacinOsvezitve === "omrezje") return route.abort("failed");
      if (st.priOsvezitvi) await st.priOsvezitvi();
      if (st.nacinOsvezitve === "5xx") return json(503, { msg: "unavailable" });
      if (st.nacinOsvezitve === "429") return json(429, { msg: "rate limit" });
      if (st.nacinOsvezitve === "zavrni" || !st.veljavniRefresh.has(telo.refresh_token)) return json(400, { error_description: "Invalid Refresh Token" });
      st.veljavniRefresh.delete(telo.refresh_token);      // enkraten, kot pri Supabase
      return json(200, st.izdaj());
    }
    if (u.pathname.endsWith("/logout")) { st.odjave++; return route.fulfill({ status: 204, headers: { "access-control-allow-origin": "*" } }); }
    return json(404, {});
  });
  await ctx.route(origin + "/**", async (route) => {
    const u = new URL(route.request().url());
    if (u.pathname === "/me" || u.pathname.startsWith("/admin/api/")) {
      const tok = (route.request().headers().authorization || "").replace(/^Bearer /, "");
      if (!st.veljavniDostop.has(tok)) return route.fulfill({ status: 401, body: "Invalid token." });
      if (Object.prototype.hasOwnProperty.call(st.odgovori, u.pathname)) return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(st.odgovori[u.pathname]) });
      if (u.pathname === "/me") return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ email: "admin@primer.si", role: "admin" }) });
      if (u.pathname === "/admin/api/summary") return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ clubs: 3, users: 7, new_applications: 0 }) });
      return route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
    }
    return route.continue();
  });
}

async function hrambe(page) {
  return page.evaluate(() => {
    const vzemi = (s) => { try { return Object.fromEntries(Object.entries(s).filter(([k]) => k.startsWith("outly_admin_"))); } catch (e) { return { napaka: String(e) }; } };
    return { loc: vzemi(localStorage), ses: vzemi(sessionStorage) };
  });
}
async function cakaj(pogoj, ms = 5000) {            // poizvedovanje po stanju stuba (namesto fiksnih zakasnitev)
  const t0 = Date.now();
  while (!pogoj()) { if (Date.now() - t0 > ms) throw new Error("cakanje na stanje je poteklo"); await new Promise(r => setTimeout(r, 25)); }
}
const prazno = (o) => Object.keys(o).length === 0;
async function panelVidnost(page) {
  return page.evaluate(() => ({
    panel: !document.getElementById("panel").classList.contains("skrito"),
    prijava: !document.getElementById("prijava").classList.contains("skrito"),
    napaka: document.getElementById("pNapaka").textContent,
  }));
}
function beleziKonzolo(page, zbirka) {
  page.on("console", (m) => { if (m.type() === "error") zbirka.push("console: " + m.text()); });
  page.on("pageerror", (e) => zbirka.push("pageerror: " + e.message));
}
// 401 nase stub-osnove je pricakovan del osvezevanja (brskalnik ga izpise kot »Failed to load resource«).
const brezPricakovanih = (z) => z.filter(x => !/status of 401|net::ERR_FAILED/.test(x));

async function vpisi(page, origin, zapomni) {
  await page.goto(origin + "/admin/");
  await page.fill("#pEmail", "admin@primer.si");
  await page.fill("#pGeslo", "geslo");
  if (zapomni) await page.check("#pZapomni");
  await page.click("#pGumb");
  await page.waitForFunction(() => !document.getElementById("panel").classList.contains("skrito"), null, { timeout: 5000 });
}


const MAPA = process.env.SHOTS || "";
if (MAPA) fs.mkdirSync(MAPA, { recursive: true });
const DOLGO = "dolgo.ime.uporabnika.za.preizkus.prelomov@zelo-dolga-domena-za-preizkus.example.si";
const klubi = Array.from({ length: 6 }, (_, i) => ({ id: i + 1, name: i === 2 ? "Klub z zelo dolgim imenom, ki se mora prelomiti v vec vrstic na telefonu" : "Klub " + (i + 1), city: "Ljubljana", address: "Dolgi naslov " + (i + 1) + ", 1000 Ljubljana",
  country: "Slovenija", owner_email: i === 1 ? DOLGO : "lastnik" + i + "@primer.si", owner_username: "lastnik" + i, genres: ["techno", "house"], min_age: 18, commission_bps: i % 2 ? 500 : null, is_organizer: i === 4, is_official: i === 0,
  seller_complete: i !== 3, lat: 46.0511, lng: 14.5051, event_count: i * 3, hidden: i === 5, is_demo: i === 4, stripe_charges_enabled: i < 2, logo_url: null }));
const uporabniki = Array.from({ length: 7 }, (_, i) => ({ id: i + 1, email: i === 1 ? DOLGO : "uporabnik" + i + "@primer.si", username: "uporabnik" + i, phone: i % 2 ? "+38640123456" : "", country: "SI", role: ["user", "business", "admin", "user", "backup", "user", "user"][i],
  email_verified: i !== 2, locked_until: i === 3 ? "2099-01-01T00:00:00Z" : null, failed_login_count: i === 3 ? 5 : 0, club_count: i % 3, created_at: "2026-09-0" + (i + 1) + "T10:00:00Z", onboarded_at: i === 5 ? null : "2026-09-01T10:00:00Z" }));
const dogodki = Array.from({ length: 5 }, (_, i) => ({ id: i + 1, club_id: 1, club_name: "Klub 1", club_hidden: false, title: i === 1 ? "Zelo dolg naslov dogodka za preizkus prelomov v seznamu na telefonu" : "Dogodek " + (i + 1), poster_url: "", start_at: "2026-11-0" + (i + 1) + "T21:00:00Z", end_at: null,
  min_age: 18, genres: ["techno"], status: i === 3 ? "draft" : "published", ticket_price_cents: 1500, currency: "EUR", ticket_url: "", created_at: "2026-10-01T10:00:00Z", capacity: 300, sold_count: 10 * i, sales_paused: i === 2,
  sales_open_at: null, sales_close_at: null, vip_enabled: false, paid_orders: i, paid_cents: i * 1500, test_paid_orders: 0, test_paid_cents: 0 }));
const nujno = { nepregledanih: 1, zadnjih_24h: 1, meja_24h: 3, items: [{ id: 7, dejanje: "event.ustavi_prodajo", cilj_tip: "event", cilj_id: 3, cilj_naslov: "Dogodek 3", nujno_at: "2026-10-23T08:00:00Z", nujno_pregledano_at: null,
  spremembe: { sales_paused: true }, prej: { sales_paused: false }, nujno_potrditev: "potrjujem: ustavi prodajo Dogodek 3", nujno_seja: "https://claude.ai/code/session_x", agent_zeton_id: 1, zeton_ime: "agent", mail: "poslan" }] };
const ZAVIHKI = ["pregled", "opozorila", "dogodki", "prosnje", "klubi", "uporabniki", "predlogi", "agent", "prijave", "vracila", "finance", "guest", "pomoc"];
const LJUDJE = ["prosnje", "klubi", "uporabniki"], VEC = ["predlogi", "agent", "prijave", "vracila", "finance", "guest", "pomoc"];

(async () => {
  const strezi = http.createServer((req, res) => {
    if (req.url === "/admin/" || req.url.startsWith("/admin/index.html")) { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); return res.end(STRAN); }
    const mod = /^\/admin\/([a-z_-]+\.(js|css))$/.exec(req.url.split("?")[0]);
    if (mod && fs.existsSync(path.join(__dirname, "..", "admin", mod[1]))) {
      res.writeHead(200, { "content-type": mod[2] === "js" ? "text/javascript; charset=utf-8" : "text/css; charset=utf-8" });
      return res.end(fs.readFileSync(path.join(__dirname, "..", "admin", mod[1])));
    }
    res.writeHead(200, { "content-type": "text/html" }); res.end("<!doctype html><title>-</title>");
  });
  await new Promise(r => strezi.listen(parseInt(process.env.ADMIN_TEST_PORT || "8743", 10), "127.0.0.1", r));
  const origin = "http://localhost:" + strezi.address().port;
  const brskalnik = await chromium.launch({ executablePath: najdiChromium(), args: ["--host-resolver-rules=MAP localhost 127.0.0.1"] });
  const posnetki = [];
  try {
    for (const [sirina, visina] of [[393, 852], [360, 740], [1280, 900]]) {
      const telefon = sirina <= 640;
      const st = novStub();
      st.odgovori["/admin/api/clubs"] = klubi; st.odgovori["/admin/api/users"] = uporabniki; st.odgovori["/admin/api/events"] = dogodki;
      st.odgovori["/admin/api/summary"] = { clubs: 6, hidden_clubs: 1, users: 7, business_users: 1, admins: 1, events: 5, upcoming_events: 4, new_applications: 2, refunds_attention: 1, open_disputes: 0, dispute_recovery_attention: 0, predlogi_caka: 2, nujno_nepregledanih: 1 };
      st.odgovori["/admin/api/predlogi/nujno"] = nujno;
      st.odgovori["/admin/api/creator-applications"] = [{ id: 4, business_name: "Bar Test", business_type: "bar", licence_id: "", message: "Pozdrav", contact_name: "Ana", contact_role: "lastnica", email: DOLGO, phone: "", user_id: null, club_id: null, city: "Maribor", business_address: "", created_at: "2026-10-01T10:00:00Z", status: "new", decided_at: null, decision_note: "" }];
      const ctx = await brskalnik.newContext({ viewport: { width: sirina, height: visina }, deviceScaleFactor: 1, hasTouch: telefon, isMobile: telefon });
      await namestiStub(ctx, st, origin);
      const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      await vpisi(page, origin, false);
      await page.waitForSelector("#nujno_pas .nj-pas", { timeout: 5000 });
      const ime = (s) => `${sirina}px ${s}`;
      const snemi = async (oznaka) => { if (!MAPA) return; const p = path.join(MAPA, `${sirina}-${oznaka}.png`); await page.screenshot({ path: p, fullPage: false }); posnetki.push(p); };
      const prelivanje = () => page.evaluate(() => ({ doc: document.documentElement.scrollWidth, okno: window.innerWidth, telo: document.body.scrollWidth }));
      const brezDrsenja = async (opis) => { const o = await prelivanje(); preveri(o.doc <= o.okno && o.telo <= o.okno, `${opis}: brez vodoravnega drsenja strani`, o); };
      const vidno = (sel) => page.evaluate((s) => { const e = document.querySelector(s); if (!e) return false; const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return cs.display !== "none" && cs.visibility !== "hidden" && r.width > 0 && r.height > 0; }, sel);
      const aktivna = () => page.evaluate(() => { const s = [...document.querySelectorAll("section[id^=z-]")].filter(e => !e.classList.contains("skrito")).map(e => e.id.slice(2)); return s; });
      const poNavigaciji = async (z) => { await page.waitForFunction((x) => { const e = document.getElementById("z-" + x); return e && !e.classList.contains("skrito"); }, z, { timeout: 5000 }); await page.waitForTimeout(150); };

      preveri(await vidno("#spodnja_vrstica") === telefon, ime("spodnja vrstica je vidna samo na telefonu"));
      preveri(await vidno("nav") === !telefon, ime("vrsta gumbov <nav> je vidna samo na racunalniku"));
      preveri(await vidno("#nujno_pas .nj-pas"), ime("rdeci pas nujnih dejanj je viden"));
      await brezDrsenja(ime("pregled"));
      await snemi("1-danes");

      if (telefon) {
        const tipke = await page.$$eval("#spodnja_vrstica > button", (b) => b.map((x) => x.querySelector("span:nth-child(2)").textContent));
        preveri(JSON.stringify(tipke) === JSON.stringify(["Danes", "Dogodki", "Opozorila", "Ljudje", "Več"]), ime("5 tipk: Danes, Dogodki, Opozorila, Ljudje, Več"), tipke);
        const sirine = await page.$$eval("#spodnja_vrstica > button", (b) => b.map((x) => Math.round(x.getBoundingClientRect().width)));
        preveri(sirine.every((w) => w >= 60) && sirine.length === 5, ime("tipke so dovolj siroke za prst (>= 60 px)"), sirine);
        preveri((await page.$$eval("#spodnja_vrstica > button", (b) => b.map((x) => x.getBoundingClientRect().height))).every((v) => v >= 44), ime("tipke so visoke >= 44 px"));
        const zn = await page.$$eval("#spodnja_vrstica .n:not(.skrito)", (b) => b.map((x) => x.textContent));
        preveri(zn.length >= 1, ime("znacke stevilk so prenesene v vrstico"), zn);
        for (const z of ["dogodki", "opozorila", "pregled"]) {
          await page.click(`#spodnja_vrstica button[data-t="${z}"]`); await poNavigaciji(z);
          preveri((await page.getAttribute(`#spodnja_vrstica button[data-t="${z}"]`, "aria-current")) === "page", ime(`tipka ${z} je aktivna`));
          await brezDrsenja(ime(z));
          if (z === "dogodki") await snemi("2-dogodki");
          if (z === "opozorila") await snemi("3-opozorila");
        }
        for (const [tipka, skupina, ime2] of [["ljudje", LJUDJE, "ljudje"], ["vec", VEC, "vec"]]) {
          for (const z of skupina) {
            await page.click(`#spodnja_vrstica button[data-t="${tipka}"]`);
            await page.waitForSelector("#lista:not(.skrito)", { timeout: 3000 });
            if (z === skupina[0]) { await brezDrsenja(ime(`lista ${ime2} odprta`)); await snemi(`4-lista-${ime2}`);
              const lr = await page.evaluate(() => { const r = document.getElementById("lista").getBoundingClientRect(); const b = document.getElementById("spodnja_vrstica").getBoundingClientRect(); return { dno: Math.round(r.bottom), vrh: Math.round(b.top), levo: r.left, desno: r.right, sirina: innerWidth }; });
              preveri(lr.dno <= lr.vrh + 1 && lr.levo >= 0 && lr.desno <= lr.sirina, ime(`lista ${ime2} stoji nad vrstico in v zaslonu`), lr); }
            await page.click(`#lista button[data-z="${z}"]`); await poNavigaciji(z);
            preveri((await aktivna()).join() === z, ime(`${z} dosegljiv prek »${tipka}«`), await aktivna());
            preveri(await vidno("#lista") === false, ime(`lista se po izbiri zapre (${z})`));
            preveri((await page.getAttribute(`#spodnja_vrstica button[data-t="${tipka}"]`, "aria-current")) === "page", ime(`tipka »${tipka}« je aktivna na ${z}`));
            await brezDrsenja(ime(z));
            if (["klubi", "uporabniki", "predlogi", "agent", "prosnje"].includes(z)) await snemi("5-" + z);
          }
        }
        // Esc in klik na ozadje zapreta listo
        await page.click('#spodnja_vrstica button[data-t="vec"]'); await page.keyboard.press("Escape");
        preveri(await vidno("#lista") === false, ime("Esc zapre listo"));
        await page.click('#spodnja_vrstica button[data-t="ljudje"]'); await page.mouse.click(sirina / 2, 40);
        preveri(await vidno("#lista") === false, ime("klik na ozadje zapre listo"));
        // kartice: tabela ni vec tabela
        await page.click('#spodnja_vrstica button[data-t="ljudje"]'); await page.click('#lista button[data-z="klubi"]'); await poNavigaciji("klubi");
        const kart = await page.evaluate(() => ({ trs: [...document.querySelectorAll("#kTabela tbody tr")].map((r) => getComputedStyle(r).display), th: getComputedStyle(document.querySelector("#kTabela thead")).display, tabela: document.getElementById("kTabela").scrollWidth <= document.getElementById("kTabela").clientWidth }));
        preveri(kart.trs.length === 6 && kart.trs.every((d) => d === "grid") && kart.th === "none" && kart.tabela, ime("Klubi: 6 kartic (grid), glava skrita, brez notranjega drsenja"), kart);
        const gumbiK = await page.$$eval("#kTabela tbody tr:first-child button", (b) => b.map((x) => { const r = x.getBoundingClientRect(); return r.right <= innerWidth && r.left >= 0 && r.height >= 30; }));
        preveri(gumbiK.length >= 3 && gumbiK.every(Boolean), ime("Klubi: gumbi Uredi/Demo/Skrij so v zaslonu"), gumbiK);
        await page.click('#spodnja_vrstica button[data-t="ljudje"]'); await page.click('#lista button[data-z="uporabniki"]'); await poNavigaciji("uporabniki");
        await page.waitForSelector("#uTabela tbody tr");
        const kartU = await page.evaluate(() => ({ trs: [...document.querySelectorAll("#uTabela tbody tr")].map((r) => getComputedStyle(r).display), tabela: document.getElementById("uTabela").scrollWidth <= document.getElementById("uTabela").clientWidth,
          izbira: [...document.querySelectorAll("#uTabela select")].every((s) => s.getBoundingClientRect().right <= innerWidth) }));
        preveri(kartU.trs.length === 7 && kartU.trs.every((d) => d === "grid") && kartU.tabela && kartU.izbira, ime("Uporabniki: 7 kartic, brez notranjega drsenja, izbira vloge v zaslonu"), kartU);
        // spremembo vloge je se vedno treba potrditi (okno potrdi()), izbira sama ne klice API-ja
        // rdeci pas ostane viden na vsakem zavihku
        preveri(await vidno("#nujno_pas .nj-pas"), ime("rdeci pas je viden tudi na Uporabnikih"));
        preveri(await vidno("#nujno_trak") === false, ime("trak ni viden, dokler je pas v zaslonu"));
        await page.evaluate(() => window.scrollTo(0, 900)); await page.waitForTimeout(250);
        const trak = await page.evaluate(() => { const e = document.getElementById("nujno_trak"); const r = e.getBoundingClientRect(); return { vidno: getComputedStyle(e).display !== "none", vrh: Math.round(r.top), besedilo: e.textContent, desno: Math.round(r.right), okno: innerWidth }; });
        preveri(trak.vidno && trak.vrh >= 0 && trak.vrh < 20 && /nujnem/.test(trak.besedilo) && trak.desno <= trak.okno, ime("po drsenju iz pasu ostane viden rdeci trak nujnega dejanja"), trak);
        await snemi("6-trak");
        await page.click("#nujno_trak"); await page.waitForTimeout(700);
        const nazaj = await page.evaluate(() => Math.round(document.getElementById("nujno_pas").getBoundingClientRect().top));
        preveri(nazaj >= -2 && nazaj < 60, ime("dotik na trak vrne na rdeci pas"), nazaj);
        await page.evaluate(() => window.scrollTo(0, 0));
      } else {
        for (const z of ZAVIHKI) {
          await page.click(`nav button[data-z="${z}"]`); await poNavigaciji(z);
          await brezDrsenja(ime(z));
          if (["klubi", "uporabniki", "dogodki"].includes(z)) await snemi("5-" + z);
        }
        const tabela = await page.evaluate(() => getComputedStyle(document.querySelector("#uTabela thead")).display);
        preveri(tabela !== "none", ime("Uporabniki ostanejo tabela na racunalniku"), tabela);
      }
      preveri(brezPricakovanih(k).length === 0, ime("konzola brez napak"), k);
      await ctx.close();
    }
  } finally { await brskalnik.close(); strezi.close(); }
  console.log("\nPosnetki zaslona: " + posnetki.length); for (const p of posnetki) console.log("  " + p);
  console.log(napake ? `\n${napake} NAPAK` : "\nVSE OK");
  process.exit(napake ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
