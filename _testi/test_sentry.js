#!/usr/bin/env node
/**
 * Sentry za backend (issue #87, sentry.js). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_sentry.js
 * Lazni ingest (http://kljuc@localhost:3138/1) zbira ovojnice, ki jih posilja @sentry/node; nikamor drugam se ne poslje nic.
 *
 *   a  brez SENTRY_DSN se @sentry/node NE naloži (ne v sentry.js, ne v index.js) in console.error ostane izvirni
 *   b  z DSN: nobena instrumentacija (Module.require, http, fetch niso zakrpani, OpenTelemetry brez ponudnika, samo 4 izrecne integracije,
 *      brez sledenja)
 *   c  backend z DSN normalno odgovarja (200), 500 v poti (GET /events?clubId=abc) pride do ingesta: sklad, vzorec poti, environment/release,
 *      NI Authorization/Cookie/X-Guest-Token/e-naslova/query niza; isti 500 ponovno = ni novega dogodka (omejitev); vrstica »POZOR« ob zagonu = warning
 *   d  napakaRocnik in odgovoriNaNapako porocata, napaka povezave (503) ne
 *   e  ocisti(): odstrani request.*, user, IP, extra, breadcrumbe; ociscenje besedil
 *   f  neujeta izjema in neujeta zavrnitev IZVEN Expressa (tudi AbortError): dogodek pride do ingesta IN proces izstopi s kodo != 0 (kot brez Sentryja, I10)
 *   g  ociscenje je hitro (K1) in skrije public_ref ter vrednosti v narekovajih; ključ omejitve nima uporabniske vsebine (S2); loceni urni proracun POZOR / 500
 *
 * Opombe: (1) test c je odvisen od tega, da GET /events?clubId=abc vrne 500 (pg 22P02); ce kdo clubId validira (400), mora izbrati drugo pot s 500.
 * (2) Otroci te skripte dobijo okolje brez SENTRY_DSN (okolje()); drugi testi, ki dvignejo otroke, ga ne brisejo - ce kdo v lupini izvozi SENTRY_DSN,
 * ga podedujejo (sentry.js bi se vklopil in poskusil poslati na ta naslov). V CI in v `npm test` DSN ni nastavljen.
 */
const http = require("http");
const zlib = require("zlib");
const { spawn, spawnSync } = require("child_process");
const path = require("path");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3137, INGEST_PORT = 3138, JWKS_PORT = 3937;
const BASE = `http://127.0.0.1:${PORT}`;
const KOREN = path.join(__dirname, "..");
const DSN = `http://kljuc@localhost:${INGEST_PORT}/1`;

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms));
async function cakaj(pogoj, ms = 8000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(50); } return false; }

// ---------- lazni ingest ----------
const dogodki = [];     // razclenjeni dogodki (type "event")
let ovojnic = 0;
const ingest = http.createServer((req, res) => {
  const kosi = [];
  req.on("data", (d) => kosi.push(d));
  req.on("end", () => {
    try {
      let telo = Buffer.concat(kosi);
      if (req.headers["content-encoding"] === "gzip") telo = zlib.gunzipSync(telo);
      ovojnic++;
      const vrstice = telo.toString("utf8").split("\n");
      for (let i = 1; i < vrstice.length - 1; i += 2) {
        const glava = JSON.parse(vrstice[i]);
        if (glava.type === "event") { const d = JSON.parse(vrstice[i + 1]); d._surovo = vrstice[i + 1]; dogodki.push(d); }
      }
    } catch (e) { console.error("ingest:", e.message); }
    res.writeHead(200, { "content-type": "application/json" }); res.end("{}");
  });
});

// Okolje otroka: brez posrednikov (proxy v oblacni seji bi lahko prestregel lokalni ingest)
function okolje(dodatno) {
  const o = { ...process.env, ...dodatno };
  for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"]) delete o[k];
  o.NO_PROXY = "localhost,127.0.0.1"; o.no_proxy = "localhost,127.0.0.1";
  if (!("SENTRY_DSN" in dodatno)) delete o.SENTRY_DSN;
  return o;
}
function otrok(koda, dodatno) {
  const r = spawnSync("node", ["-e", koda], { cwd: KOREN, env: okolje(dodatno), encoding: "utf8", timeout: 20000 });
  return r;
}

(async () => {
  await new Promise((r) => ingest.listen(INGEST_PORT, r));
  let srv = null;
  try {
    console.log("\n# a  brez SENTRY_DSN se nic ne nalozi");
    let r = otrok(`const s=require("./sentry");const e0=console.error;s.zagon();
      console.log("RES="+JSON.stringify({vklopljen:s.vklopljen(),sentryVCache:Object.keys(require.cache).some(k=>/node_modules\\/@sentry\\//.test(k)),otelVCache:Object.keys(require.cache).some(k=>/node_modules\\/@opentelemetry\\//.test(k)),izvirniConsole:console.error===e0}))`, {});
    let rez = JSON.parse((r.stdout.match(/RES=(.*)/) || [, "{}"])[1]);
    assert(rez.vklopljen === false && rez.sentryVCache === false && rez.otelVCache === false, "sentry.js brez DSN: paket @sentry/node in OpenTelemetry nista v require.cache", rez);
    assert(rez.izvirniConsole === true, "brez DSN console.error ni zakrpan");
    r = otrok(`process.env.PORT="${PORT + 20}";process.env.SUPABASE_URL="http://127.0.0.1:${JWKS_PORT}";require("./index.js");
      setTimeout(()=>{console.log("RES="+JSON.stringify({sentryVCache:Object.keys(require.cache).some(k=>/node_modules\\/@sentry\\//.test(k)),otelVCache:Object.keys(require.cache).some(k=>/node_modules\\/@opentelemetry\\//.test(k)),uncaught:process.listeners("uncaughtException").length,rejection:process.listeners("unhandledRejection").length}));process.exit(0)},1500)`,
      { DATABASE_URL: DB });
    rez = JSON.parse((r.stdout.match(/RES=(.*)/) || [, "{}"])[1] || "{}");
    assert(rez.sentryVCache === false && rez.otelVCache === false, "celoten index.js brez DSN: @sentry/node in OpenTelemetry se ne naložita", [rez, r.stderr.slice(-300)]);
    assert(rez.uncaught === 0 && rez.rejection === 0, "index.js brez DSN: nobenega poslušalca uncaughtException/unhandledRejection (I10: Node privzeto)", rez);
    assert(!/\[sentry\]/.test(r.stdout + r.stderr), "brez DSN ni nobene vrstice [sentry] v dnevniku");

    console.log("\n# b  z DSN: nobena instrumentacija, samo izrecne integracije");
    r = otrok(`const M=require("module"),http=require("http"),https=require("https");
      const a={req:M.prototype.require,load:M._load,rq:http.request,g:http.get,srq:https.request,e:http.Server.prototype.emit,end:http.ServerResponse.prototype.end,f:globalThis.fetch};
      const s=require("./sentry");const e0=console.error;s.zagon();
      const S=require("@sentry/node");const o=S.getClient().getOptions();
      const otel=require("@opentelemetry/api");
      console.log("RES="+JSON.stringify({vklopljen:s.vklopljen(),
        zakrpano:{req:M.prototype.require!==a.req,load:M._load!==a.load,request:http.request!==a.rq,get:http.get!==a.g,srequest:https.request!==a.srq,emit:http.Server.prototype.emit!==a.e,end:http.ServerResponse.prototype.end!==a.end,fetch:globalThis.fetch!==a.f},
        integracije:o.integrations.map(i=>i.name).sort(),traces:o.tracesSampleRate===undefined,pii:o.sendDefaultPii,breadcrumbi:o.maxBreadcrumbs,
        ponudnik:otel.trace.getTracerProvider().getDelegate().constructor.name,
        sdkTrace:Object.keys(require.cache).some(k=>/sdk-trace-node|context-async-hooks|auto-instrumentations/.test(k)),
        env:o.environment,release:o.release,console:console.error!==e0}))`, { SENTRY_DSN: DSN, RENDER: "1", RENDER_GIT_COMMIT: "abc123def" });
    rez = JSON.parse((r.stdout.match(/RES=(.*)/) || [, "{}"])[1] || "{}");
    assert(rez.vklopljen === true, "z DSN je Sentry vklopljen", [rez, r.stderr.slice(-300)]);
    assert(rez.zakrpano && Object.values(rez.zakrpano).every((x) => x === false), "Module.require, http, https, fetch, ServerResponse NISO zakrpani", rez.zakrpano);
    assert(JSON.stringify(rez.integracije) === JSON.stringify(["Dedupe", "LinkedErrors", "OnUncaughtException"]), "samo 3 izrecne integracije (brez http/pg/express/console; zavrnitve ureja lasten poslusalec)", rez.integracije);
    assert(rez.traces === true && rez.pii === false && rez.breadcrumbi === 0, "brez sledenja, sendDefaultPii=false, brez breadcrumbov", [rez.traces, rez.pii, rez.breadcrumbi]);
    assert(rez.ponudnik === "NoopTracerProvider" && rez.sdkTrace === false, "OpenTelemetry brez ponudnika (noop), brez SDK sledenja", [rez.ponudnik, rez.sdkTrace]);
    assert(rez.env === "production" && rez.release === "abc123def", "environment=production (RENDER), release=RENDER_GIT_COMMIT", [rez.env, rez.release]);

    console.log("\n# c  backend z DSN: normalen odgovor, 500 pride do ingesta brez osebnih podatkov");
    srv = spawn("node", ["index.js"], { cwd: KOREN, env: okolje({ PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
      SENTRY_DSN: DSN, RENDER: "1", RENDER_GIT_COMMIT: "abc123def", STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "", JAVNI_PREDPOMNILNIK_MS: "0", REZERVACIJE_CISCENJE_MS: "0" }), stdio: ["ignore", "pipe", "pipe"] });
    let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
    let gor = false;
    for (let i = 0; i < 100 && !gor; i++) { try { await fetch(BASE + "/clubs"); gor = true; } catch { await pocakaj(100); } }
    assert(gor, "backend z SENTRY_DSN se zazene");
    assert(/\[sentry\] vklopljen \(environment=production\)/.test(log), "dnevnik: [sentry] vklopljen", log.slice(0, 300));
    let a = await fetch(BASE + "/clubs"), b = await fetch(BASE + "/events");
    assert(a.status === 200 && b.status === 200, "GET /clubs in GET /events -> 200 (aplikacija z DSN normalno odgovarja)", [a.status, b.status]);

    const poz = await cakaj(() => dogodki.some((d) => d.level === "warning" && /POZOR/.test(d.message || "")));
    assert(poz, "vrstica »POZOR« ob zagonu (testni nacin placil) je prišla kot warning", dogodki.map((d) => [d.level, d.message]));
    const pozD = dogodki.find((d) => d.level === "warning");
    assert(pozD && !/sk_|whsec_|@/.test(pozD.message) && /POZOR: placila v TESTNEM nacinu/.test(pozD.message), "opozorilo POZOR brez skrivnosti (samo ociscen stavek)", pozD && pozD.message);

    const SKRIVNOSTI = ["Bearer x", "gt_skrivnost_123", "piskot_skrivnost", "ana.tajna@primer.si", "X-Guest-Token", "tajni-xoutly"];
    const r500 = await fetch(BASE + "/events?clubId=abc&epos=ana.tajna@primer.si", { headers: { Authorization: "Bearer x", "X-Guest-Token": "gt_skrivnost_123", Cookie: "sid=piskot_skrivnost", "X-Outly-Club": "tajni-xoutly" } });
    assert(r500.status === 500 && (await r500.text()) === "Server error.", "GET /events?clubId=abc -> 500 »Server error.« (odgovor nespremenjen)", r500.status);
    const prisel = await cakaj(() => dogodki.some((d) => d.tags && d.tags.kontekst === "odgovor-500"));
    assert(prisel, "500 v poti je prišel do ingesta");
    const d500 = dogodki.find((d) => d.tags && d.tags.kontekst === "odgovor-500") || {};
    assert(d500.tags && d500.tags.pot === "/events" && d500.tags.metoda === "GET", "oznaki metoda=GET, pot=/events (vzorec poti)", d500.tags);
    assert(d500.exception && d500.exception.values && d500.exception.values[0].stacktrace && d500.exception.values[0].stacktrace.frames.length > 0, "dogodek ima izjemo s skladom (iz console.error(e) pred 500)");
    assert(d500.environment === "production" && d500.release === "abc123def", "environment=production, release=RENDER_GIT_COMMIT", [d500.environment, d500.release]);
    assert(SKRIVNOSTI.every((s) => !(d500._surovo || "").includes(s)), "v dogodku ni Authorization, Cookie, X-Guest-Token, X-Outly-Club, e-naslova", SKRIVNOSTI.filter((s) => (d500._surovo || "").includes(s)));
    assert(!("request" in d500) && !("user" in d500), "dogodek nima polj request in user");
    assert(!/clubId=abc|epos=/.test(d500._surovo || ""), "v dogodku ni query niza");
    assert(/invalid input syntax for type [a-z]+: \[x\]/.test(((d500.exception || {}).values || [{}])[0].value || ""), "pg napaka ne ponovi vhodne vrednosti", ((d500.exception || {}).values || [{}])[0].value);

    const stPrej = dogodki.length;
    await fetch(BASE + "/events?clubId=abd");          // isti kljuc (metoda + pot + sporocilo) -> omejitev 15 min
    await pocakaj(600);
    const ponovitev = dogodki.slice(stPrej).filter((d) => d.tags && d.tags.kontekst === "odgovor-500" && d.tags.pot === "/events");
    assert(ponovitev.length === 0, "isti 500 znova v 15 min ne naredi novega dogodka (omejitev)", ponovitev.length);

    console.log("\n# d  napakaRocnik in odgovoriNaNapako (v tem procesu, z lazno ingest DSN)");
    process.env.SENTRY_DSN = DSN; process.env.RENDER = ""; delete process.env.RENDER_GIT_COMMIT;
    for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]) delete process.env[k];
    process.env.NO_PROXY = process.env.no_proxy = "localhost,127.0.0.1";
    const sentry = require("../sentry");
    assert(sentry.zagon() === true && sentry.vklopljen(), "sentry.zagon() v testnem procesu");
    const { napakaRocnik } = require("../asinhroni_rocniki");
    const { odgovoriNaNapako } = require("../napaka_povezave");
    const lazniRes = () => ({ headersSent: false, locals: {}, kode: [], status(c) { this.kode.push(c); return this; }, set() { return this; }, send() { return this; }, json() { return this; } });
    const req1 = { method: "POST", path: "/x/12345", baseUrl: "", route: { path: "/x/:id" } };
    const res1 = lazniRes();
    napakaRocnik(new Error("kaos v rocniku ana.tajna@primer.si"), req1, res1, () => {});
    assert(res1.kode[0] === 500, "napakaRocnik: odgovor 500 nespremenjen", res1.kode);
    assert(await cakaj(() => dogodki.some((x) => x.tags && x.tags.kontekst === "rocnik")), "napakaRocnik: dogodek pride do ingesta");
    const dR = dogodki.find((x) => x.tags && x.tags.kontekst === "rocnik");
    assert(dR && dR.tags.pot === "/x/:id" && dR.tags.metoda === "POST" && !dR._surovo.includes("ana.tajna@primer.si") && !dR._surovo.includes("12345"), "napakaRocnik: vzorec poti brez id-ja, e-naslov skrit", dR && dR.tags);
    assert(res1.locals.sentryPoslano === true, "napakaRocnik: zahtevek oznacen kot porocan (brez dvojnega porocila ob res.status)");
    const res2 = lazniRes();
    odgovoriNaNapako(res2, new Error("sken je padel"), "POST /business/tickets/scan");
    assert(res2.kode[0] === 500 && await cakaj(() => dogodki.some((x) => x.tags && x.tags.kontekst === "POST /business/tickets/scan")), "odgovoriNaNapako: 500 in dogodek");
    const pred503 = dogodki.length;
    const res3 = lazniRes();
    odgovoriNaNapako(res3, Object.assign(new Error("Connection terminated unexpectedly"), {}), "GET /me");
    napakaRocnik(Object.assign(new Error("tezava"), { code: "ECONNRESET" }), { method: "GET", path: "/p" }, lazniRes(), () => {});
    sentry.porociNapako(new Error("sentinela"), "sentinela");
    await cakaj(() => dogodki.some((x) => x.tags && x.tags.kontekst === "sentinela"));
    assert(res3.kode[0] === 503 && dogodki.slice(pred503).every((x) => x.tags && x.tags.kontekst === "sentinela"), "napaka povezave (503) se NE poroca", dogodki.slice(pred503).map((x) => x.tags));

    console.log("\n# e  ocisti() in ociscenje()");
    const sirov = { message: "napaka za a.b@c.si z Bearer abc123 in eyJhbGciOi.eyJzdWIiOi.podpis ter cs_live_a1b2c3d4e5", request: { headers: { Authorization: "Bearer x", Cookie: "c=1", "X-Guest-Token": "t" }, data: { email: "a@b.si" }, cookies: { c: "1" }, query_string: "a=1", url: "http://x/y?z=1" },
      user: { email: "a@b.si", ip_address: "1.2.3.4", id: 5 }, server_name: "host", breadcrumbs: [{ message: "x" }], extra: { telo: "a@b.si", unhandledPromiseRejection: true }, contexts: { request: {}, trace: {}, runtime: { name: "node" } },
      exception: { values: [{ type: "Error", value: "kljuc (email)=(a@b.si)", stacktrace: { frames: [{ filename: "x.js", vars: { a: "tajno" } }] } }] }, tags: { pot: "/events", kontekst: "x@y.si" } };
    const c = sentry.ocisti(JSON.parse(JSON.stringify(sirov)));
    assert(c && !("request" in c) && !("user" in c) && !("server_name" in c) && c.breadcrumbs.length === 0, "request, user, server_name, breadcrumbi odstranjeni");
    assert(JSON.stringify(c.extra) === '{"unhandledPromiseRejection":true}' && !("request" in c.contexts) && !("trace" in c.contexts) && c.contexts.runtime.name === "node", "extra le dovoljeno, contexts.request/trace odstranjena");
    assert(!/a\.b@c\.si|abc123|eyJ|cs_live|a@b\.si|tajno|x@y\.si/.test(JSON.stringify(c)), "besedila ociscena (e-naslov, Bearer, JWT, ids, vars)", c);
    assert(sentry.ociscenje('violates "club_members_user_id_fkey"') === 'violates "club_members_user_id_fkey"', "imena omejitev brez stevk ostanejo berljiva");

    console.log("\n# g  ociscenje: hitrost, public_ref, vrednosti v narekovajih, ključ omejitve, loceni proracuni");
    for (const N of [16000, 32000]) for (const enota of ["a", "a-", "a1-"]) {
      const sporocilo = `invalid input syntax for type integer: "${enota.repeat(N)}"`;
      const drugo = enota.repeat(N);
      const t0 = process.hrtime.bigint(); const o1 = sentry.ociscenje(sporocilo); const o2 = sentry.ociscenje(drugo);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      assert(ms < 20 && o1.length <= 301 && o2.length <= 301, `ociscenje ${N} x "${enota}" (sporocilo + golo besedilo) < 20 ms in <= 300 znakov`, [ms.toFixed(1), o1.length, o2.length]);
    }
    assert(sentry.ociscenje("POZOR: narocilo OUT-ABCD2345 NI mogoce; test_Ab12Cd34") === "POZOR: narocilo [ref] NI mogoce; [ref]", "public_ref (OUT-XXXXXXXX, test_…) skrit", sentry.ociscenje("POZOR: narocilo OUT-ABCD2345 NI mogoce; test_Ab12Cd34"));
    assert(sentry.ociscenje('value "99999999999" is out of range for type integer') === 'value "[x]" is out of range for type integer', "22003: vrednost v narekovajih skrita");
    assert(sentry.ociscenje('time zone "ana@tajna.si" not recognized') === 'time zone "[x]" not recognized', "time zone: vrednost v narekovajih skrita");
    assert(sentry.ociscenje('invalid input syntax for type timestamp with time zone: "x\nvrstica2"') === "invalid input syntax for type timestamp with time zone: [x]", "22P02 z novo vrstico skrit v celoti");
    assert(sentry.ociscenje('violates "club_members_user_id_fkey" constraint') === 'violates "club_members_user_id_fkey" constraint', "ime omejitve ostane berljivo");
    // S2: 30 razlicnih uporabniskih vrednosti = en vzrok = en dogodek
    const predS2 = dogodki.length;
    for (let i = 0; i < 30; i++) await fetch(BASE + `/events?clubId=zzz${i}vrednost${i * 7}`);
    await fetch(BASE + "/clubs?limit=1&city=" + "x".repeat(10));   // nic za Sentry
    await pocakaj(800);
    const s2 = dogodki.slice(predS2).filter((d) => d.tags && d.tags.kontekst === "odgovor-500");
    assert(s2.length === 0, "30 razlicnih clubId (isti vzrok kot prej poslani 500) ne naredi novih dogodkov (kljuc brez uporabniske vsebine)", s2.length);
    // Loceni proracun: 12 opozoril (meja 10/h) ne porabi proracuna za napake
    const opoz = []; for (let i = 0; i < 12; i++) opoz.push(sentry.ocisti({ level: "warning", message: "POZOR " + i }));
    assert(opoz.filter(Boolean).length <= 10, "opozorila POZOR: najvec 10/h", opoz.filter(Boolean).length);
    assert(sentry.ocisti({ level: "error", message: "napaka" }) !== null, "proracun za napake je locen od opozoril");
    assert(sentry.ocisti({ level: "fatal", message: "x", exception: { values: [{ mechanism: { handled: false } }] } }) !== null, "fatalne gredo vedno skozi");

    console.log("\n# f  neujeta izjema / zavrnitev izven Expressa: dogodek + izstop s kodo != 0");
    for (const [ime, koda, kontekstBesedila] of [
      ["uncaughtException", `setTimeout(()=>{throw new Error("boom-izjema ana.tajna@primer.si")},50)`, "boom-izjema"],
      ["unhandledRejection", `setTimeout(()=>{Promise.reject(new Error("boom-zavrnitev ana.tajna@primer.si"))},50)`, "boom-zavrnitev"],
      ["unhandledRejection (AbortError)", `setTimeout(()=>{const e=new Error("boom-abort ana.tajna@primer.si");e.name="AbortError";Promise.reject(e)},50)`, "boom-abort"],
    ]) {
      const pred = dogodki.length;
      const rr = spawnSync("node", ["-e", `require("./sentry").zagon();${koda};setInterval(()=>{},1000)`], { cwd: KOREN, env: okolje({ SENTRY_DSN: DSN }), encoding: "utf8", timeout: 20000 });
      assert(rr.status !== null && rr.status !== 0, `${ime}: proces z DSN izstopi s kodo != 0 (kot brez Sentryja)`, [rr.status, rr.signal, (rr.stderr || "").slice(-200)]);
      assert(await cakaj(() => dogodki.slice(pred).some((x) => ((x.exception || {}).values || []).some((v) => (v.value || "").includes(kontekstBesedila)))), `${ime}: dogodek je prišel do ingesta pred izstopom (flush)`);
      const dd = dogodki.slice(pred).find((x) => ((x.exception || {}).values || []).some((v) => (v.value || "").includes(kontekstBesedila)));
      assert(dd && !dd._surovo.includes("ana.tajna@primer.si") && dd.level === "fatal", `${ime}: stopnja fatal, e-naslov skrit`, dd && dd.level);
    }
    // Isto brez DSN: proces izstopi s kodo != 0 (Node privzeto), brez dogodka
    const pred = dogodki.length;
    for (const koda of [`setTimeout(()=>{throw new Error("brez-sentryja")},50)`, `setTimeout(()=>{Promise.reject(new Error("brez-sentryja"))},50)`, `setTimeout(()=>{const e=new Error("brez-sentryja");e.name="AbortError";Promise.reject(e)},50)`]) {
      const rr = spawnSync("node", ["-e", `require("./sentry").zagon();${koda};setInterval(()=>{},1000)`], { cwd: KOREN, env: okolje({}), encoding: "utf8", timeout: 20000 });
      assert(rr.status !== null && rr.status !== 0, "brez DSN: proces izstopi s kodo != 0 (vedenje nespremenjeno)", [rr.status, rr.signal]);
    }
    await pocakaj(300);
    assert(dogodki.length === pred, "brez DSN ni nobenega dogodka");

    assert(!/TypeError|ReferenceError|Unhandled/.test(log.replace(/invalid input syntax/g, "")), "dnevnik backenda brez neujetih napak", log.slice(-400));
  } finally {
    if (srv) srv.kill();
    ingest.close();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
