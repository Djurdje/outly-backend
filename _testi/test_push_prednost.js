#!/usr/bin/env node
/**
 * Test: PREDNOSTNA VRSTA PUSHA (#277 N3, I47). Zagon (lokalno; baza NI potrebna, potreben je `openssl`):
 *   node _testi/test_push_prednost.js
 * Brez backenda: `push_apns.js` neposredno proti lazni HTTP/2 APNs strezniku (samopodpisan certifikat, ustvarjen v testu; NODE_TLS_REJECT_UNAUTHORIZED=0
 * velja samo v tem procesu). Lazni APNs ZADRZI vsak zahtevek, dokler ga test ne sprosti, zato so sloti zasedeni toliko casa, kolikor hoce test;
 * brez casovnih mej v stenski uri: test caka na POGOJ (prispel zahtevek), vrstni red sprostitev doloca test.
 *
 * Pred popravkom je bila ena FIFO vrsta: push natakarju (table_service) je cakal za vsemi cakajocimi mnozicnimi obvestili (sledilci kluba: tisoci).
 *  1  tipi: table_service, ticket_received, guest_list_invite = operativno; club_event in neznan tip = mnozicno
 *  2  operativni push ne caka na mnozicno vrsto: ko so sloti za mnozicne zasedeni in 27 mnozicnih caka, operativni prispe takoj (rezerviran slot)
 *  3  sproscen slot gre cakajocemu operativnemu pred cakajocimi mnozicnimi, a po APNS_OPERATIVNIH_ZAPORED zaporednih ena mnozicna (brez stradanja)
 *  4  vrsti sta locena: polna mnozicna vrsta (vrsta_polna) ne zavrne operativnega; polna operativna ne zavrne mnozicnega
 *  5  APNS_SOCASNO=1: brez rezerve, operativni se vseeno uvrsti pred cakajoce mnozicne; obvestilo brez prednosti = mnozicno (stari klicatelji)
 */
const crypto = require("crypto");
const http2 = require("http2");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";   // samo ta proces: lazni APNs ima samopodpisan certifikat
const { ustvariApns, sestaviObvestilo } = require("../push_apns");

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const cakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function pocakaj(pogoj, ms = 5000) {   // ms je samo zgornja meja za primer napake; uspeh pride takoj, ko je pogoj izpolnjen
  const konec = Date.now() + ms;
  while (Date.now() < konec) { if (await pogoj()) return true; await cakaj(5); }
  return false;
}

// --- lazni APNs, ki zadrzi zahtevke ---
const mapa = fs.mkdtempSync(path.join(os.tmpdir(), "outly-push-prednost-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", path.join(mapa, "k.pem"), "-out", path.join(mapa, "c.pem"),
  "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { stdio: "ignore" });
const P8_B64 = Buffer.from(crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" })).toString("base64");
let prispeli = [];            // oznake v vrstnem redu prihoda
let zadrzani = [];            // { stream, oznaka } se neodgovorjeni
const oznakaZetona = new Map();
const zeton = (oznaka) => { const z = crypto.createHash("sha256").update("prednost-" + oznaka).digest("hex"); oznakaZetona.set(z, oznaka); return z; };
const apnsStreznik = http2.createSecureServer({ key: fs.readFileSync(path.join(mapa, "k.pem")), cert: fs.readFileSync(path.join(mapa, "c.pem")) });
apnsStreznik.on("session", (s) => s.on("error", () => {}));
apnsStreznik.on("stream", (stream, glave) => {
  stream.on("error", () => {});
  stream.resume();
  stream.on("end", () => {
    const oznaka = oznakaZetona.get(String(glave[":path"]).split("/").pop());
    prispeli.push(oznaka);
    zadrzani.push({ stream, oznaka });
  });
});
function sprosti(n = 1) {   // odgovori 200 na n najstarejsih zadrzanih zahtevkov
  for (let i = 0; i < n; i++) {
    const z = zadrzani.shift();
    if (!z) return;
    try { z.stream.respond({ ":status": 200 }); z.stream.end(""); } catch { /* zaprt */ }
  }
}
const sprostiVse = () => sprosti(zadrzani.length);
// Sprosti zahtevke, dokler se vse obljube ne izpolnijo (tudi ob napaki testa se ne zatakne: zgornja meja je stevilo krogov, ne cas).
async function izprazni(obljube) {
  let koncano = false;
  const vse = Promise.all(obljube).then((r) => { koncano = true; return r; });
  for (let i = 0; i < 2000 && !koncano; i++) { sprostiVse(); await cakaj(5); }
  return vse;
}
const tihiDnevnik = { log() {}, error() {} };
const operativno = sestaviObvestilo({ tip: "table_service", id: 1, naslov: "VIP table", kljuc: "VIP table %@ is ready to be served", argumenti: ["A1"] });
const mnozicno = sestaviObvestilo({ tip: "club_event", id: 2, naslov: "New event", kljuc: "%@ posted a new event: %@", argumenti: ["K", "E"] });

function novApns(okolje, port) {
  return ustvariApns({ APNS_KEY_ID: "TESTKEYID1", APNS_TEAM_ID: "TESTTEAM12", APNS_KEY_P8: P8_B64, APNS_HOST: `https://localhost:${port}`, APNS_TIMEOUT_MS: "60000", ...okolje }, tihiDnevnik);
}

(async () => {
  await new Promise(r => apnsStreznik.listen(0, r));
  const port = apnsStreznik.address().port;
  const apnsi = [];
  try {
    console.log("\n# 1. Tipi obvestil");
    for (const tip of ["table_service", "ticket_received", "guest_list_invite"]) {
      assert(sestaviObvestilo({ tip, id: 1, naslov: "x", kljuc: "y" }).prednost === "operativno", `${tip} = operativno`);
    }
    assert(sestaviObvestilo({ tip: "club_event", id: 1, naslov: "x", kljuc: "y" }).prednost === "mnozicno", "club_event = mnozicno");
    assert(sestaviObvestilo({ tip: "nekaj_novega", id: 1, naslov: "x", kljuc: "y" }).prednost === "mnozicno", "neznan tip = mnozicno (kot doslej)");
    assert(operativno.velja === 3600 || operativno.velja === 24 * 3600, "obstojeca polja (velja) so ostala");
    assert(!("prednost" in JSON.parse(operativno.telo)) && !operativno.telo.includes("operativno"), "prednost NI v vsebini obvestila (payload ostane isti)");

    console.log("\n# 2. Operativni push ne caka na mnozicno vrsto");
    {
      const a = novApns({ APNS_SOCASNO: "4", APNS_REZERVA: "1", APNS_OPERATIVNIH_ZAPORED: "3", APNS_VRSTA_NAJVEC: "100" }, port); apnsi.push(a);
      const mnozicni = Array.from({ length: 30 }, (_, i) => a.poslji(zeton("M" + (i + 1)), mnozicno));
      assert(await pocakaj(() => prispeli.length === 3), "mnozicni zasedejo 3 od 4 slotov (1 rezerviran za operativne)", prispeli);
      const op1 = a.poslji(zeton("O1"), operativno);
      assert(await pocakaj(() => prispeli.length === 4), "operativni push prispe, ceprav caka 27 mnozicnih", prispeli);
      assert(prispeli[3] === "O1" && prispeli.filter(x => x[0] === "M").length === 3, "4. zahtevek je operativni (rezerva), mnozicnih je se vedno 3", prispeli);

      console.log("\n# 3. Sproscen slot gre operativnemu; po 3 zaporednih ena mnozicna");
      const operativni = [];
      for (let i = 2; i <= 11; i++) operativni.push(a.poslji(zeton("O" + i), operativno));   // 10 cakajocih operativnih
      const pred = prispeli.length;
      for (let i = 1; i <= 13; i++) { sprosti(1); if (!(await pocakaj(() => prispeli.length === pred + i))) break; }
      const zaporedje = prispeli.slice(pred).map(x => x[0] === "O" ? x : "M");
      // O1 (dodeljen ob cakajocih mnozicnih) steje v zaporedje: meja 3 = O1, O2, O3, nato ena mnozicna. Po O11 operativnih ni vec in rezerviran slot ostane prost.
      const pricakovano = ["O2", "O3", "M", "O4", "O5", "O6", "M", "O7", "O8", "O9", "M", "O10", "O11"];
      assert(JSON.stringify(zaporedje) === JSON.stringify(pricakovano), "vrstni red: po 3 zaporednih operativnih ena mnozicna (brez stradanja), vmes operativni pred cakajocimi mnozicnimi", zaporedje);
      prispeli = [];
      const vsi = await izprazni([op1, ...operativni, ...mnozicni]);
      vsi.splice(0, 11);
      assert(vsi.length === 30 && vsi.every(r => r.ok), "vseh 30 mnozicnih je na koncu dostavljenih (nobeno ni izgubljeno)", vsi.filter(r => !r.ok).length);
    }

    console.log("\n# 4. Locena vrsti: polna ena ne zavrne druge");
    {
      prispeli = []; zadrzani = [];
      const a = novApns({ APNS_SOCASNO: "2", APNS_REZERVA: "1", APNS_VRSTA_NAJVEC: "3" }, port); apnsi.push(a);
      const m = [];
      for (let i = 1; i <= 4; i++) m.push(a.poslji(zeton("m" + i), mnozicno));            // 1 v teku, 3 v vrsti
      assert(await pocakaj(() => prispeli.length === 1), "mnozicni: 1 v teku (2. slot je rezerviran)", prispeli);
      const preveliki = await a.poslji(zeton("m5"), mnozicno);
      assert(preveliki.ok === false && preveliki.razlog === "vrsta_polna", "5. mnozicni: vrsta_polna (mnozicna vrsta polna)", preveliki);
      const o = [];
      for (let i = 1; i <= 4; i++) o.push(a.poslji(zeton("o" + i), operativno));          // 1 v teku (rezerva), 3 v operativni vrsti
      assert(await pocakaj(() => prispeli.length === 2), "operativni gre kljub polni mnozicni vrsti", prispeli);
      const o5 = await a.poslji(zeton("o5"), operativno);
      assert(o5.ok === false && o5.razlog === "vrsta_polna", "5. operativni: vrsta_polna (operativna vrsta polna)", o5);
      const rez = await izprazni([...m, ...o]);
      assert(rez.filter(r => r.ok).length === 8, "vseh 8 sprejetih je na koncu dostavljenih", rez.map(r => r.ok));
    }

    console.log("\n# 5. APNS_SOCASNO=1 (brez rezerve) in obvestilo brez prednosti");
    {
      prispeli = []; zadrzani = [];
      const a = novApns({ APNS_SOCASNO: "1", APNS_REZERVA: "5", APNS_VRSTA_NAJVEC: "100" }, port); apnsi.push(a);
      const p1 = a.poslji(zeton("a1"), mnozicno);
      assert(await pocakaj(() => prispeli.length === 1), "en slot: prvi mnozicni gre (rezerva je omejena na socasno - 1 = 0)", prispeli);
      const p2 = a.poslji(zeton("a2"), mnozicno), p3 = a.poslji(zeton("a3"), { telo: mnozicno.telo, velja: mnozicno.velja });   // a3: brez polja prednost
      const po = a.poslji(zeton("ao"), operativno);
      sprosti(1);
      assert(await pocakaj(() => prispeli.length === 2), "po sprostitvi pride na vrsto operativni", prispeli);
      assert(prispeli[1] === "ao", "operativni je pred prej cakajocima mnozicnima (a2, a3)", prispeli);
      const rez = await izprazni([p1, p2, p3, po]);
      assert(rez.every(r => r.ok) && prispeli.join(",") === "a1,ao,a2,a3", "obvestilo brez prednosti = mnozicno, vrstni red FIFO znotraj razreda", prispeli);
    }
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    for (const a of apnsi) { try { a.zapri(); } catch { /* ignoriraj */ } }
    sprostiVse();
    try { apnsStreznik.close(); } catch { /* ignoriraj */ }
    try { fs.rmSync(mapa, { recursive: true, force: true }); } catch { /* ignoriraj */ }
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
