#!/usr/bin/env node
/**
 * Test dnevnika povezav (issue #139): enkrat na okno vrstica `[povezave] ...` s stevilom novih povezav, zahtevkov, odprtih
 * povezav in zamikom zanke dogodkov; brez prometa ni vrstice; DNEVNIK_POVEZAV_MS=0 izklopi dnevnik.
 * Zagon (lokalno, PG16, baza z vsemi migracijami; baza je potrebna samo, da proces zazene):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_dnevnik_povezav.js
 * Porta 3180 (dnevnik vklopljen, okno 300 ms) in 3181 (izklopljen). Trditve niso odvisne od casovanja ali meje okna: vsaka vrstica se
 * caka POGOJNO (do 15 s), stevila so vsote cez vsa okna in tocna (v procesu ni drugega prometa, ker se pripravljenost bere iz izpisa, ne s sondo).
 * Negativni trditvi (ni vrstice brez prometa / ob izklopu) cakata fiksen cas, ki lahko test le zamudi, nikoli pokvari.
 */
const { spawn } = require("child_process");
const http = require("http");
const net = require("net");
const fs = require("fs");
const os = require("os");
const path = require("path");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3180, PORT_B = 3181, OKNO_MS = 300;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const spi = (ms) => new Promise(r => setTimeout(r, ms));
async function pocakaj(pogoj, msg, rok = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < rok) { const v = pogoj(); if (v) return v; await spi(25); }
  assert(false, `${msg} (iztek ${rok} ms)`); return null;
}

// Predlozek: ob SIGUSR2 zanka dogodkov 400 ms stoji (sinhrono), da je zamik zanke merljiv.
const blokada = path.join(os.tmpdir(), `blokada_zanke_${process.pid}.js`);
fs.writeFileSync(blokada, "process.on('SIGUSR2', () => { const t = Date.now(); while (Date.now() - t < 400); });\n");

function zazeni(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, REZERVACIJE_CISCENJE_MS: "0", PORT: String(port), DATABASE_URL: DB, SUPABASE_URL: "http://127.0.0.1:1", RESEND_API_KEY: "", QR_SECRET: "test", NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --require ${blokada}`.trim(), ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const st = { srv, log: "" };
  srv.stdout.on("data", d => st.log += d); srv.stderr.on("data", d => st.log += d);
  st.vrstice = () => st.log.split("\n").filter(v => v.startsWith("[povezave]"));
  st.razclenjene = () => st.vrstice().map(v => { const m = v.match(/^\[povezave\] 300 ms: novih (\d+), zahtevkov (\d+), odprtih (\d+), zamik zanke p99 (\d+\.\d) ms, max (\d+\.\d) ms$/); return m ? { novih: +m[1], zahtevkov: +m[2], odprtih: +m[3], p99: +m[4], max: +m[5] } : null; });
  return st;
}
const pripravljen = (st) => pocakaj(() => st.log.includes("Server running on port"), "strežnik se je zagnal");
// Zahtevek na NOVI povezavi (brez vzdrzevanja): agent z keepAlive: false pošlje Connection: close.
function getNovaPovezava(port) {
  return new Promise((res, rej) => {
    const r = http.get({ host: "127.0.0.1", port, path: "/", agent: new http.Agent({ keepAlive: false }) }, (x) => { x.resume(); x.on("end", () => res(x.statusCode)); });
    r.on("error", rej);
  });
}

(async () => {
  const A = zazeni(PORT_A, { DNEVNIK_POVEZAV_MS: String(OKNO_MS) });
  const B = zazeni(PORT_B, { DNEVNIK_POVEZAV_MS: "0" });
  try {
    await pripravljen(A); await pripravljen(B);

    console.log("Brez prometa ni vrstice:");
    await spi(5 * OKNO_MS);
    assert(A.vrstice().length === 0, "5 oken brez prometa: nobene vrstice [povezave]", A.vrstice());

    console.log("5 zahtevkov na 5 novih povezavah:");
    const statusi = [];
    for (let i = 0; i < 5; i++) statusi.push(await getNovaPovezava(PORT_A));
    assert(statusi.every(s => s === 200), "GET / -> 200 (5 x)", statusi);
    const vsota = (k) => A.razclenjene().filter(Boolean).reduce((a, v) => a + v[k], 0);
    await pocakaj(() => vsota("novih") >= 5 && vsota("zahtevkov") >= 5, "vrstice zajamejo 5 novih povezav in 5 zahtevkov");
    assert(A.razclenjene().every(Boolean), "vsaka vrstica ima obliko `[povezave] 300 ms: novih N, zahtevkov M, odprtih K, zamik zanke p99 X ms, max Y ms`", A.vrstice());
    assert(vsota("novih") === 5 && vsota("zahtevkov") === 5, "tocno 5 novih povezav in 5 zahtevkov", { novih: vsota("novih"), zahtevkov: vsota("zahtevkov") });
    assert(A.razclenjene().every(v => v && v.max >= v.p99 - 0.2), "max >= p99 v vsaki vrstici", A.vrstice());
    const stVrstic = A.vrstice().length;
    await spi(5 * OKNO_MS);
    assert(A.vrstice().length === stVrstic, "po koncu prometa se vrstice ne dodajajo (5 oken)", A.vrstice().slice(stVrstic));

    console.log("Odprte povezave (3 vzdrzevane, mirujoce):");
    const vtici = [];
    for (let i = 0; i < 3; i++) {
      const s = net.connect(PORT_A, "127.0.0.1");
      s.on("error", () => {});
      await new Promise(r => s.once("connect", r));
      let telo = ""; s.on("data", d => telo += d);
      s.write("GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n");
      s.odgovor = () => telo;
      vtici.push(s);
    }
    await pocakaj(() => vtici.every(s => /^HTTP\/1\.1 200/.test(s.odgovor())), "vse 3 povezave dobijo odgovor 200");
    const odOd = (k) => A.razclenjene().slice(stVrstic).filter(Boolean).reduce((a, v) => a + v[k], 0);
    const z = await pocakaj(() => A.razclenjene().slice(stVrstic).find(v => v && v.odprtih === 3 && v.zahtevkov >= 1), "vrstica z odprtih 3 in vsaj 1 zahtevkom");
    assert(!!z, "vrstica z `odprtih 3` (3 mirujoce vzdrzevane povezave)", z);
    await pocakaj(() => odOd("novih") >= 3 && odOd("zahtevkov") >= 3, "vrstice zajamejo 3 nove povezave in 3 zahtevke");
    assert(odOd("novih") === 3 && odOd("zahtevkov") === 3, "tocno 3 nove povezave in 3 zahtevki (vsota cez okna)", { novih: odOd("novih"), zahtevkov: odOd("zahtevkov") });
    for (const s of vtici) s.destroy();

    console.log("Zamik zanke (zanka stoji 400 ms):");
    // Promet tece ves cas (vsako okno ima vrstico). Zastoj sprozimo ~100 ms po izpisu vrstice, torej dolgo po ponastavitvi
    // histograma (prvi vzorec po reset() se zavrze, zato zastoj ne sme zaceti tik po njej) in 200 ms pred koncem okna.
    let konec = false;
    const posiljalec = (async () => { while (!konec) { await getNovaPovezava(PORT_A).catch(() => {}); await spi(60); } })();
    const stPrej = A.vrstice().length;
    await pocakaj(() => A.vrstice().length > stPrej, "nova vrstica pred zastojem");
    await spi(100);
    const prej = A.vrstice().length;
    A.srv.kill("SIGUSR2");
    const zamik = await pocakaj(() => A.razclenjene().slice(prej).find(v => v && v.max >= 100), "vrstica z max zamikom >= 100 ms (zanka je stala 400 ms)");
    konec = true; await posiljalec; if (!zamik) console.log(A.log);
    assert(zamik && zamik.max >= 100, "izmerjen zamik zanke >= 100 ms", zamik);
    assert(zamik && zamik.max < 5000, "zamik zanke je v ms in razumen (< 5 s)", zamik);

    console.log("Izklop (DNEVNIK_POVEZAV_MS=0):");
    for (let i = 0; i < 3; i++) await getNovaPovezava(PORT_B);
    await spi(10 * OKNO_MS);
    assert(B.vrstice().length === 0, "ob izklopu in prometu ni nobene vrstice [povezave]", B.vrstice());
    assert(!B.log.includes("DNEVNIK_POVEZAV_MS"), "izklop (0) ni javljen kot neveljavna vrednost", B.log);
  } finally {
    A.srv.kill(); B.srv.kill();
    try { fs.unlinkSync(blokada); } catch {}
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
