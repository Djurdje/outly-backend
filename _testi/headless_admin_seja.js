// Headless preverjanje seje admin panela (kljukica »Zapomni si me«, osvezevanje zetona, odjava).
// NI v `npm test` (ta je izrecen seznam skript, zato se ta datoteka ne zazene sama): rabi Playwright + Chromium,
// ki nista odvisnosti repozitorija (CI ju nima). Zazeni rocno pred PR-jem, ki se dotakne admin/index.html (seja, prijava, XSS):
//   NODE_PATH="$(npm root -g)" node _testi/headless_admin_seja.js
// Chromium: PW_CHROMIUM=/pot/do/chrome ali samodejno /opt/pw-browsers/chromium-*/chrome-linux/chrome
// (nikoli `playwright install`). Stubana sta samo Supabase Auth in backend (`page.route`), panel strezemo
// iz lokalnega streznika na istem izvoru kot API (kot Express: /admin/ + /me + /admin/api/*).
// Izhodna koda 1, ce kaj odpove.

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

(async () => {
  const strezi = http.createServer((req, res) => {
    if (req.url === "/admin/" || req.url.startsWith("/admin/index.html")) { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); return res.end(STRAN); }
    // Moduli panela (DECISIONS 21. 10. 2026: vec datotek): dialog.js, dogodki.js, dogodki.css iz mape admin/.
    const mod = /^\/admin\/([a-z_]+\.(js|css))$/.exec(req.url.split("?")[0]);
    if (mod && fs.existsSync(path.join(__dirname, "..", "admin", mod[1]))) {
      res.writeHead(200, { "content-type": mod[2] === "js" ? "text/javascript; charset=utf-8" : "text/css; charset=utf-8" });
      return res.end(fs.readFileSync(path.join(__dirname, "..", "admin", mod[1])));
    }
    res.writeHead(200, { "content-type": "text/html" }); res.end("<!doctype html><title>-</title>");   // prazna stran istega izvora (nastavitev sessionStorage)
  });
  await new Promise(r => strezi.listen(parseInt(process.env.ADMIN_TEST_PORT || "8742", 10), "127.0.0.1", r));
  const origin = "http://localhost:" + strezi.address().port;
  // localhost -> 127.0.0.1: streznik poslusa na 127.0.0.1, Chromium localhost razresi tja
  const brskalnik = await chromium.launch({ executablePath: najdiChromium(), args: ["--host-resolver-rules=MAP localhost 127.0.0.1"] });
  const nov = async (opts) => { const st = novStub(); const ctx = await brskalnik.newContext(opts); await namestiStub(ctx, st, origin); return { ctx, st }; };

  try {
    // ---- kljukica obstaja, privzeto neoznacena ----
    {
      const { ctx } = await nov({}); const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      await page.goto(origin + "/admin/");
      const c = await page.evaluate(() => { const e = document.getElementById("pZapomni"); return e ? { checked: e.checked, besedilo: e.closest("label").textContent.trim(), sirina: e.getBoundingClientRect().width } : null; });
      preveri(c && c.checked === false && c.besedilo === "Zapomni si me" && c.sirina < 30, "kljukica »Zapomni si me« je pod geslom, privzeto neoznacena, ni raztegnjena", c);
      preveri(k.length === 0, "konzola brez napak (prijavni obrazec)", k);
      await ctx.close();
    }

    // ---- (a) oznaceno: localStorage, preziv zapiranja brskalnika ----
    {
      const { ctx, st } = await nov({}); const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      await vpisi(page, origin, true);
      const h = await hrambe(page);
      preveri(h.loc.outly_admin_token === "A-1" && h.loc.outly_admin_refresh === "R-1" && !!h.loc.outly_admin_jaz && prazno(h.ses), "(a) oznaceno: zetoni v localStorage, sessionStorage prazen", h);
      const stanje = await ctx.storageState();                       // localStorage da, sessionStorage ne = ponovni zagon brskalnika
      const ctx2 = await brskalnik.newContext({ storageState: stanje }); await namestiStub(ctx2, st, origin);
      const p2 = await ctx2.newPage(); beleziKonzolo(p2, k);
      await p2.goto(origin + "/admin/");
      await p2.waitForFunction(() => !document.getElementById("panel").classList.contains("skrito"), null, { timeout: 5000 });
      const v = await panelVidnost(p2);
      preveri(v.panel && !v.prijava, "(a) nov kontekst z istim storage state je ze prijavljen", v);
      preveri(await p2.evaluate(() => document.querySelectorAll("#stevilke .stevilka").length) > 0, "(a) panel je naložil podatke");
      preveri(brezPricakovanih(k).length === 0, "(a) konzola brez napak", k);
      await ctx2.close(); await ctx.close();
    }

    // ---- (b) neoznaceno: sessionStorage, nov zavihek/kontekst odjavljen ----
    {
      const { ctx, st } = await nov({}); const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      await vpisi(page, origin, false);
      const h = await hrambe(page);
      preveri(h.ses.outly_admin_token === "A-1" && h.ses.outly_admin_refresh === "R-1" && prazno(h.loc), "(b) neoznaceno: zetoni v sessionStorage, localStorage prazen", h);
      const zavihek = await ctx.newPage(); beleziKonzolo(zavihek, k);
      await zavihek.goto(origin + "/admin/");
      const v1 = await panelVidnost(zavihek);
      preveri(v1.prijava && !v1.panel, "(b) nov zavihek v istem kontekstu je odjavljen", v1);
      const ctx2 = await brskalnik.newContext({ storageState: await ctx.storageState() }); await namestiStub(ctx2, st, origin);
      const p2 = await ctx2.newPage(); await p2.goto(origin + "/admin/");
      const v2 = await panelVidnost(p2);
      preveri(v2.prijava && !v2.panel, "(b) nov kontekst z istim storage state je odjavljen", v2);
      preveri(brezPricakovanih(k).length === 0, "(b) konzola brez napak", k);
      await ctx2.close(); await ctx.close();
    }

    // ---- (c) zastarel dostopni zeton + veljaven refresh: osvezi, novi zetoni v ISTI hrambi ----
    for (const trajna of [true, false]) {
      const ime = trajna ? "localStorage" : "sessionStorage";
      const st = novStub(); st.veljavniRefresh.add("R-stari");
      const origins = [{ origin, localStorage: trajna ? [{ name: "outly_admin_token", value: "STALE" }, { name: "outly_admin_refresh", value: "R-stari" }, { name: "outly_admin_jaz", value: JSON.stringify({ email: "admin@primer.si", role: "admin" }) }] : [] }];
      const ctx = await brskalnik.newContext({ storageState: { cookies: [], origins } }); await namestiStub(ctx, st, origin);
      const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      if (!trajna) {                                                   // sessionStorage: nastavi v strani in naloži znova
        await page.goto(origin + "/admin/");
        await page.evaluate(() => { sessionStorage.setItem("outly_admin_token", "STALE"); sessionStorage.setItem("outly_admin_refresh", "R-stari"); sessionStorage.setItem("outly_admin_jaz", JSON.stringify({ email: "admin@primer.si", role: "admin" })); });
      }
      await page.goto(origin + "/admin/");
      await page.waitForFunction(() => document.querySelectorAll("#stevilke .stevilka").length > 0, null, { timeout: 5000 }).catch(() => {});
      const v = await panelVidnost(page), h = await hrambe(page);
      preveri(v.panel && !v.prijava, `(c) ${ime}: zastarel dostopni zeton + veljaven refresh -> ostane prijavljen`, v);
      preveri(st.osvezitve.length === 1 && st.osvezitve[0] === "R-stari", `(c) ${ime}: tocno ena osvezitev z osveževalnim zetonom iz hrambe`, st.osvezitve);
      const kje = trajna ? h.loc : h.ses, drugje = trajna ? h.ses : h.loc;
      preveri(kje.outly_admin_token === "A-1" && kje.outly_admin_refresh === "R-1" && prazno(drugje), `(c) ${ime}: novi zetoni zapisani v isto hrambo, druga prazna`, h);
      preveri(await page.evaluate(() => document.querySelectorAll("#stevilke .stevilka").length) > 0, `(c) ${ime}: podatki panela naloženi po osvežitvi`);
      preveri(brezPricakovanih(k).length === 0, `(c) ${ime}: konzola brez napak`, k);
      await ctx.close();
    }

    // ---- (c2) samo refresh (dostopni izginil) ----
    {
      const st = novStub(); st.veljavniRefresh.add("R-stari");
      const origins = [{ origin, localStorage: [{ name: "outly_admin_refresh", value: "R-stari" }, { name: "outly_admin_jaz", value: JSON.stringify({ email: "admin@primer.si", role: "admin" }) }] }];
      const ctx = await brskalnik.newContext({ storageState: { cookies: [], origins } }); await namestiStub(ctx, st, origin);
      const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      await page.goto(origin + "/admin/");
      await page.waitForFunction(() => document.querySelectorAll("#stevilke .stevilka").length > 0, null, { timeout: 5000 }).catch(() => {});
      const v = await panelVidnost(page), h = await hrambe(page);
      preveri(v.panel && h.loc.outly_admin_token === "A-1" && h.loc.outly_admin_refresh === "R-1", "(c2) samo refresh v localStorage -> osvezi in ostane prijavljen", { v, h });
      await ctx.close();
    }

    // ---- (c3) refresh zavrnjen: obe hrambi pociscene, prijava ----
    {
      const st = novStub(); st.nacinOsvezitve = "zavrni";
      const jaz = JSON.stringify({ email: "admin@primer.si", role: "admin" });
      const origins = [{ origin, localStorage: [{ name: "outly_admin_token", value: "STALE" }, { name: "outly_admin_refresh", value: "R-mrtev" }, { name: "outly_admin_jaz", value: jaz }] }];
      const ctx = await brskalnik.newContext({ storageState: { cookies: [], origins } }); await namestiStub(ctx, st, origin);
      const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      await page.goto(origin + "/nic");                              // prazna stran istega izvora, samo za nastavitev sessionStorage
      await page.evaluate((j) => { sessionStorage.setItem("outly_admin_token", "STALE2"); sessionStorage.setItem("outly_admin_refresh", "R-mrtev2"); sessionStorage.setItem("outly_admin_jaz", j); }, jaz);
      await page.goto(origin + "/admin/");
      await page.waitForFunction(() => !document.getElementById("prijava").classList.contains("skrito"), null, { timeout: 5000 }).catch(() => {});
      const v = await panelVidnost(page), h = await hrambe(page);
      preveri(v.prijava && !v.panel && /potekla/.test(v.napaka), "(c3) zavrnjena osvezitev -> prijava s sporocilom", v);
      preveri(prazno(h.loc) && prazno(h.ses), "(c3) zavrnjena osvezitev pocisti OBE hrambi", h);
      await ctx.close();
    }

    // ---- (c4) omrezna napaka / 5xx / 429 pri osvezitvi NE pobrise trajne seje; sporocilo ni zavajajoce in je samo enkrat ----
    for (const nacin of ["omrezje", "5xx", "429"]) {
      const st = novStub(); st.nacinOsvezitve = nacin; st.veljavniRefresh.add("R-stari");
      const jaz = JSON.stringify({ email: "admin@primer.si", role: "admin" });
      const origins = [{ origin, localStorage: [{ name: "outly_admin_token", value: "STALE" }, { name: "outly_admin_refresh", value: "R-stari" }, { name: "outly_admin_jaz", value: jaz }] }];
      const ctx = await brskalnik.newContext({ storageState: { cookies: [], origins } }); await namestiStub(ctx, st, origin);
      const page = await ctx.newPage();
      await page.goto(origin + "/admin/");
      await page.waitForSelector(".obv.slabo", { timeout: 5000 });              // cakamo na obvestilo o napaki (osvezitev je obdelana)
      const h = await hrambe(page);
      const obv = await page.$$eval(".obv", (e) => e.map((x) => x.textContent));
      preveri(st.osvezitve.length >= 1, `(c4) ${nacin}: osvezitev se je res zgodila`, st.osvezitve);
      preveri(h.loc.outly_admin_refresh === "R-stari" && h.loc.outly_admin_token === "STALE", `(c4) osvezitev ni uspela (${nacin}) -> seja ostane v localStorage`, h);
      const pricakovano = nacin === "omrezje" ? /omrežje/ : nacin === "5xx" ? /strežnik: 503/ : /strežnik: 429/;
      preveri(obv.length === 1 && /Osvežitev seje ni uspela/.test(obv[0]) && pricakovano.test(obv[0]) && (nacin === "omrezje" || !/omrežje/.test(obv[0])), `(c4) ${nacin}: tocno eno sporocilo, brez napacnega »omrezje«`, obv);
      await ctx.close();
    }

    // ---- (c5) tekma dveh zavihkov: osvezitev zavrnjena, drug zavihek je medtem zapisal nov zeton -> ostane prijavljen ----
    {
      const st = novStub(); st.nacinOsvezitve = "zavrni";
      const jaz = JSON.stringify({ email: "admin@primer.si", role: "admin" });
      const origins = [{ origin, localStorage: [{ name: "outly_admin_token", value: "STALE" }, { name: "outly_admin_refresh", value: "R-stari" }, { name: "outly_admin_jaz", value: jaz }] }];
      const ctx = await brskalnik.newContext({ storageState: { cookies: [], origins } }); await namestiStub(ctx, st, origin);
      const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      const drug = await ctx.newPage(); await drug.goto(origin + "/nic");     // »drug zavihek« (isti localStorage)
      st.veljavniDostop.add("A-drugi"); st.veljavniRefresh.add("R-drugi");
      st.priOsvezitvi = async () => { setTimeout(() => drug.evaluate(() => { localStorage.setItem("outly_admin_token", "A-drugi"); localStorage.setItem("outly_admin_refresh", "R-drugi"); }).catch(() => {}), 100); };
      await page.goto(origin + "/admin/");
      await page.waitForFunction(() => document.querySelectorAll("#stevilke .stevilka").length > 0, null, { timeout: 5000 }).catch(() => {});
      const v = await panelVidnost(page), h = await hrambe(page);
      preveri(v.panel && !v.prijava && h.loc.outly_admin_refresh === "R-drugi", "(c5) tekma zavihkov: zavrnjena osvezitev, drug zavihek je zapisal nov zeton -> ostane prijavljen", { v, h });
      preveri(k.filter(x => !/status of (401|400)/.test(x)).length === 0, "(c5) konzola brez napak (razen pricakovanih 401/400 stuba)", k);
      await ctx.close();
    }

    // ---- (d) odjava pocisti OBE hrambi ----
    {
      const { ctx, st } = await nov({}); const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      await vpisi(page, origin, true);
      await page.evaluate(() => { sessionStorage.setItem("outly_admin_token", "ostanek"); sessionStorage.setItem("outly_admin_refresh", "ostanek"); sessionStorage.setItem("outly_admin_jaz", "{}"); });
      preveri(await page.inputValue("#pGeslo") === "", "(d) geslo je izpraznjeno ze po prijavi");
      await page.click("#jaz button");
      await page.waitForFunction(() => !document.getElementById("prijava").classList.contains("skrito"), null, { timeout: 5000 });
      await cakaj(() => st.odjave >= 1);
      const v = await panelVidnost(page), h = await hrambe(page);
      const polja = await page.evaluate(() => ({ geslo: document.getElementById("pGeslo").value, zapomni: document.getElementById("pZapomni").checked }));
      preveri(polja.geslo === "" && polja.zapomni === false, "(d) odjava izprazni geslo in odznaci »Zapomni si me«", polja);
      preveri(v.prijava && !v.panel, "(d) odjava pokaze prijavo", v);
      preveri(prazno(h.loc) && prazno(h.ses), "(d) odjava pocisti OBE hrambi", h);
      preveri(st.odjave === 1, "(d) odjava obvesti Supabase (/logout)", st.odjave);
      await page.reload();
      preveri((await panelVidnost(page)).prijava, "(d) po osvežitvi strani je se vedno odjavljen");
      preveri(brezPricakovanih(k).length === 0, "(d) konzola brez napak", k);
      await ctx.close();
    }

    // ---- (e) hramba meče izjeme (zasebni način): brez napak, seja živi v pomnilniku ----
    {
      const { ctx } = await nov({}); const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      await page.addInitScript(() => {
        const vrzi = () => { throw new DOMException("The operation is insecure.", "SecurityError"); };
        Object.defineProperty(window, "localStorage", { get: vrzi });
        Object.defineProperty(window, "sessionStorage", { get: vrzi });
      });
      await vpisi(page, origin, true);
      const v = await panelVidnost(page);
      preveri(v.panel && !v.prijava, "(e) hrambi vrzeta izjemo: prijava vseeno deluje (pomnilnik strani)", v);
      await page.click("#jaz button");
      await page.waitForFunction(() => !document.getElementById("prijava").classList.contains("skrito"), null, { timeout: 5000 });
      preveri((await panelVidnost(page)).prijava, "(e) odjava brez hrambe deluje");
      preveri(brezPricakovanih(k).length === 0, "(e) konzola brez napak", k);
      await ctx.close();
    }
    // ---- (e2) samo localStorage mece (oznaceno): rezerva je sessionStorage ----
    {
      const { ctx } = await nov({}); const page = await ctx.newPage(); const k = []; beleziKonzolo(page, k);
      await page.addInitScript(() => { Object.defineProperty(window, "localStorage", { get() { throw new DOMException("denied", "SecurityError"); } }); });
      await vpisi(page, origin, true);
      const ses = await page.evaluate(() => sessionStorage.getItem("outly_admin_token"));
      preveri(ses === "A-1", "(e2) localStorage vrze, »Zapomni si me« -> rezerva sessionStorage, panel deluje", ses);
      preveri(brezPricakovanih(k).length === 0, "(e2) konzola brez napak", k);
      await ctx.close();
    }

    // ---- (k1) XSS: nizi iz streznika (tudi stevila, id) v zavihkih panela NE smejo izvesti skripte ----
    {
      const NAK = '<img src=x onerror="window.__xss=1">';
      const st = novStub();
      const klub = { id: 1, name: NAK, city: NAK, address: NAK, country: NAK, owner_email: NAK, owner_username: NAK, genres: [NAK], min_age: NAK, commission_bps: null, is_organizer: false, is_official: false,
        seller_complete: true, lat: null, lng: null, event_count: NAK, hidden: false, stripe_charges_enabled: false, logo_url: null };
      const dogodek = { id: 2, title: NAK, genres: [NAK], min_age: NAK, club_name: NAK, club_hidden: false, start_at: "2027-01-01T20:00:00Z", end_at: null, ticket_price_cents: 1000, status: "published", paid_orders: 0, paid_cents: 0 };
      const uporabnik = { id: 3, email: NAK, username: NAK, phone: NAK, country: NAK, role: "user", email_verified: true, locked_until: null, failed_login_count: NAK, club_count: NAK, created_at: "2026-01-01T00:00:00Z", onboarded_at: "2026-01-01T00:00:00Z" };
      const prosnja = { id: 4, business_name: NAK, business_type: NAK, licence_id: NAK, message: NAK, contact_name: NAK, contact_role: NAK, email: NAK, phone: NAK, user_id: NAK, club_id: NAK, city: NAK, business_address: NAK, created_at: "2026-01-01T00:00:00Z", status: NAK, decided_at: null, decision_note: NAK };
      const zneski = { gross_cents: 100, fee_cents: 10, clubs_net_cents: 90, refunded_cents: 0, tickets_sold: NAK, orders: NAK, buyers: NAK, clubs_with_sales: NAK };
      st.odgovori["/admin/api/clubs"] = [klub];
      st.odgovori["/admin/api/events"] = [dogodek];
      st.odgovori["/admin/api/users"] = [uporabnik];
      st.odgovori["/admin/api/creator-applications"] = [prosnja];
      st.odgovori["/admin/api/summary"] = { clubs: NAK, users: NAK, new_applications: NAK, events: NAK };
      st.odgovori["/admin/api/finance"] = { from: NAK, to: NAK, fee_percent: NAK, payments_mode: "live", summary: zneski, all_time: { gross_cents: 1, fee_cents: 1, tickets_sold: NAK },
        test_summary: { orders: NAK, gross_cents: 0, fee_cents: 0, refunded_cents: 0, tickets_sold: NAK }, all_time_test: { orders: NAK, gross_cents: 0 },
        by_day: [{ day: NAK, gross_cents: 100, tickets: NAK }],
        by_club: [{ name: NAK, city: NAK, gross_cents: 1, fee_cents: 1, refunded_cents: 0, net_cents: 1, tickets_sold: NAK, orders: NAK }],
        by_event: [{ title: NAK, status: NAK, club_name: NAK, start_at: "2027-01-01T20:00:00Z", ticket_price_cents: 100, tickets_sold: NAK, capacity: NAK, checked_in: NAK, gross_cents: 1, fee_cents: 1 }],
        recent_orders: [{ public_ref: NAK, created_at: "2026-01-01T00:00:00Z", event_title: NAK, club_name: NAK, buyer_username: NAK, buyer_email: NAK, quantity: NAK, total_cents: 1, application_fee_cents: 0, refunded_cents: 0, status: NAK, is_test: false }] };
      const ctx = await brskalnik.newContext(); await namestiStub(ctx, st, origin);
      const page = await ctx.newPage(); const k = [];
      page.on("pageerror", (e) => k.push("pageerror: " + e.message));
      await vpisi(page, origin, false);
      for (const [zavihek, tabela] of [["pregled", "#stevilke"], ["klubi", "#kTabela"], ["dogodki", "#dTabela"], ["uporabniki", "#uTabela"], ["prosnje", "#prTabela"], ["finance", "#fStevilke"]]) {
        await page.click(`nav button[data-z="${zavihek}"]`);
        await page.waitForSelector(`${tabela} *`, { timeout: 5000 });
        if (zavihek === "finance") await page.waitForSelector("#fNarocila table", { timeout: 5000 });
        await page.evaluate(() => new Promise((r) => setTimeout(r, 300)));      // negativna preverba (onerror teče asinhrono): kratek premor je neizogiben
        const o = await page.evaluate((t) => ({ xss: window.__xss === undefined ? null : window.__xss, slike: document.querySelectorAll('#panel img[src="x"]').length,
          besedilo: document.querySelector(t).textContent.includes("<img src=x") }), tabela);
        preveri(o.xss === null && o.slike === 0 && o.besedilo, `(k1) zavihek ${zavihek}: skripta se ne izvede, besedilo je vidno ubezano`, o);
      }
      preveri(k.length === 0, "(k1) brez pageerror", k);
      await ctx.close();
    }

    // ---- (f) vzporedni 401 si delijo eno osvezitev ----
    {
      const st = novStub(); st.veljavniRefresh.add("R-stari");
      const origins = [{ origin, localStorage: [{ name: "outly_admin_token", value: "STALE" }, { name: "outly_admin_refresh", value: "R-stari" }, { name: "outly_admin_jaz", value: JSON.stringify({ email: "admin@primer.si", role: "admin" }) }] }];
      const ctx = await brskalnik.newContext({ storageState: { cookies: [], origins } }); await namestiStub(ctx, st, origin);
      const page = await ctx.newPage();
      await page.goto(origin + "/admin/");
      await page.waitForFunction(() => document.querySelectorAll("#stevilke .stevilka").length > 0, null, { timeout: 5000 });
      await page.evaluate(() => { localStorage.setItem("outly_admin_token", "STALE"); });
      const r = await page.evaluate(() => Promise.all([klic("GET", "/admin/api/summary"), klic("GET", "/admin/api/summary"), klic("GET", "/admin/api/summary")]).then(() => "ok", e => String(e)));
      preveri(r === "ok" && st.osvezitve.length === 2, "(f) trije vzporedni klici z zastarelim zetonom -> ena sama dodatna osvezitev", { r, osvezitve: st.osvezitve });
      await ctx.close();
    }
  } finally {
    await brskalnik.close(); strezi.close();
  }
  console.log(napake ? `\n${napake} NAPAK` : "\nVSE OK");
  process.exit(napake ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
