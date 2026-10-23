#!/usr/bin/env node
/**
 * Racun kupcu (Issue #319, I55): davcno potrjen racun ali dobropis gre kupcu v LOCENEM mailu »Vaš račun / Your invoice« s PDF-jem iz naše baze (racuni_pdf), NATANKO ENKRAT.
 * Brez nakupa in Stripa: racuni in racuni_pdf so vpisani neposredno (PDF pridobi delavec, glej test_racuni_eracuni §27), backend (lazni Resend) jih poslje iz pospravljalca.
 *   node _testi/test_racun_kupcu.js        (PG16, prazna baza z vsemi migracijami; DATABASE_URL)
 *
 *   1  racun s PDF: natanko en mail, SL + EN, priloga = PDF iz baze, noga s firmo, brez e-naslova v dnevniku; ponovni teki pospravljalca ne poslejo vec
 *   2  brez PDF mail NE gre; ko PDF prispe, gre
 *   3  dobropis: svoj mail »Vaš dobropis / Your credit note«
 *   4  napaka Resenda (znana, 4xx): ponovitev, na koncu natanko en mail
 *   5  izid neznan (rok Resenda potekel): mail se NE ponovi (kopija brez oznake KOPIJA), POZOR, mail_izid_neznan
 *   6  racun, ki ni `potrjen`; izbrisan racun (*@outly.invalid): brez maila
 *   7  dva procesa hkrati (ista baza): natanko en mail
 *   8  pot nakupa/webhooka/skena ne klice posiljanja racuna (I16): staticna preverba index.js
 */
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3231, PORT_B = 3232, JWKS_PORT = 3997, RESEND_PORT = 3999;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 600) : ""); } }
const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms));
async function cakaj(pogoj, ms = 10000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(100); } return false; }

const jwksServer = http.createServer((req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ keys: [] })); });
const R = { poslano: [], napaka: 0, zamik: 0, prispelo: 0 };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", (x) => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      if (R.napaka > 0) { R.napaka--; res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub: zavrnjeno", statusCode: 422 })); }
      const m = JSON.parse(d); R.prispelo++;
      const koncaj = () => { R.poslano.push(m); try { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ id: "mail_" + R.poslano.length })); } catch (_) { /* odjemalec je odnehal */ } };
      return R.zamik ? setTimeout(koncaj, R.zamik) : koncaj();
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const mailiNa = (email) => R.poslano.filter((m) => m.to === email || (Array.isArray(m.to) && m.to.includes(email)));

function zagon(port, okolje = {}) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    STRIPE_SECRET_KEY: "", STRIPE_POSPRAVI_MS: "3600000", PREVERI_OKNO_MS: "0", RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>",
    GOST_POSTA_PONOVI_MS: "300", GOST_POSTA_PREMOR_MS: "100", GOST_POSTA_TIMEOUT_MS: "800", GOST_POSTA_REZERVA_MS: "0", RACUN_MAIL_RAZMAK_MS: "0", RACUNI_PONUDNIK: "", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const s = { srv, log: "" };
  srv.stdout.on("data", (d) => s.log += d); srv.stderr.on("data", (d) => s.log += d);
  return s;
}
async function cakajStreznik(baza) { for (let i = 0; i < 100; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }
const ustavi = async (o) => { if (!o || o.srv.exitCode !== null) return; const k = new Promise((r) => o.srv.once("exit", r)); o.srv.kill("SIGTERM"); await Promise.race([k, pocakaj(3000)]); };

const PDF = (oznaka) => Buffer.from(`%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n% ${oznaka} ${"x".repeat(120)}\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n`);

(async () => {
  const pool = new Pool({ connectionString: DB, max: 6 });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, vracila, odpovedi_dogodkov, racuni, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await pool.query("TRUNCATE racuni_zaporedje");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  await new Promise((r) => resendServer.listen(RESEND_PORT, r));
  const uid = (await pool.query("INSERT INTO users (email, username) VALUES ('lastnik@outly.si', 'lastnik') RETURNING id")).rows[0].id;
  const klub = (await pool.query("INSERT INTO clubs (owner_user_id, name, is_official) VALUES ($1, 'Outly', TRUE) RETURNING id", [uid])).rows[0].id;
  const ev = (await pool.query("INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age) VALUES ($1, 'Launch', '2026-12-24T20:00:00+01:00', 'published', 1999, 500, 0) RETURNING id", [klub])).rows[0].id;
  let n = 0, stevilka = 100;
  async function nov({ email = null, vrsta = "racun", brezPdf = false, stanje = "potrjen", cents = 3000 } = {}) {
    n++; const naslov = email || `kupec${n}@primer.si`;
    const o = (await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email, stripe_account_id)
      VALUES ($1, $2, $3, $4, 1, $5, $5, 'paid', NOW(), $6, 'platform') RETURNING id, public_ref`, ["OUT-RK" + n, uid, ev, klub, cents, naslov])).rows[0];
    let ref = null;
    if (vrsta === "dobropis") ref = (await nov({ email: naslov, cents })).racunId;
    const r = (await pool.query("INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents) VALUES ($1, $2, $3, $4, $5) RETURNING id", [o.id, vrsta, ref, vrsta === "dobropis" ? "test-rk-" + n : null, vrsta === "dobropis" ? -cents : cents])).rows[0];
    if (vrsta === "dobropis") await pool.query("UPDATE racuni SET vracilo_uspelo = TRUE WHERE id = $1", [r.id]);
    stevilka++;
    await pool.query(`UPDATE racuni SET prostor = 'A001', naprava = '1', leto = 2026, stevilka = $2, izdan_at = NOW(), stevilka_vir = 'ponudnik', ponudnik = 'eracuni', ponudnik_id = $3, ponudnik_stevilka = $4,
        stanje = $5, eor = $6, zoi = $7, potrjen_at = NOW() WHERE id = $1`, [r.id, stevilka, "60:" + stevilka, "2026-" + String(stevilka).padStart(5, "0"),
      stanje === "potrjen" ? "potrjen" : "izdan", stanje === "potrjen" ? crypto.randomUUID() : null, crypto.randomBytes(16).toString("hex")]);
    const pdf = PDF(`${vrsta} ${stevilka}`);
    if (!brezPdf) await dodajPdf(r.id, pdf);
    return { oid: o.id, ref: o.public_ref, racunId: r.id, email: naslov, stevilka, pdf };
  }
  async function dodajPdf(id, pdf) {
    await pool.query("INSERT INTO racuni_pdf (racun_id, pdf, sha256) VALUES ($1, $2, $3)", [id, pdf, crypto.createHash("sha256").update(pdf).digest("hex")]);
    await pool.query("UPDATE racuni SET pdf_prejet = TRUE WHERE id = $1", [id]);
  }
  const vrstica = async (id) => (await pool.query("SELECT * FROM racuni WHERE id = $1", [id])).rows[0];

  let A = null, B = null;
  try {
    A = zagon(PORT_A); await cakajStreznik(`http://127.0.0.1:${PORT_A}`);

    console.log("\n# 1. Racun s PDF: natanko en mail, SL + EN, priloga iz baze");
    const K1 = await nov({ email: "ana.kupec@primer.si" });
    assert(await cakaj(async () => mailiNa(K1.email).length >= 1), "mail je poslan kupcu");
    await pocakaj(1500);   // vec tekov pospravljalca (300 ms)
    const m1 = mailiNa(K1.email);
    assert(m1.length === 1, "natanko en mail kljub ponavljajocim tekom pospravljalca", m1.length);
    const m = m1[0] || {};
    assert(/Vaš račun \/ Your invoice/.test(m.subject) && m.subject.includes(`A001-1-${K1.stevilka}`) && m.subject.includes(K1.ref), "zadeva: Vaš račun / Your invoice, številka računa, naročilo", m.subject);
    assert(/Vaš račun/.test(m.text) && /Your invoice/.test(m.text) && /Pošiljatelj \/ Sender: NEXT DIMENSIONS/.test(m.text) && /Pošiljatelj \/ Sender/.test(m.html), "dvojezično (SL + EN), noga s firmo in sedežem", m.text && m.text.slice(0, 300));
    assert(/30,00 EUR/.test(m.text) && /30\.00 EUR/.test(m.text), "znesek v obeh jezikih");
    const pri = (m.attachments || [])[0];
    assert(m.attachments && m.attachments.length === 1 && pri.content_type === "application/pdf" && /^racun-A001-1-\d+\.pdf$/.test(pri.filename) && Buffer.from(pri.content, "base64").equals(K1.pdf), "ena priloga: PDF iz racuni_pdf (bit za bit)", pri && pri.filename);
    const r1 = await vrstica(K1.racunId);
    assert(r1.mail_poslano_at !== null && r1.mail_poskusi === 1 && r1.mail_izid_neznan === false, "mail_poslano_at zapisan, en poskus", [r1.mail_poskusi]);
    assert(!A.log.includes(K1.email) && !A.log.includes(K1.pdf.toString("base64").slice(0, 40)), "dnevnik brez e-naslova in vsebine PDF");

    console.log("\n# 2. Brez PDF mail NE gre");
    const K2 = await nov({ brezPdf: true });
    await pocakaj(1500);
    assert(mailiNa(K2.email).length === 0 && (await vrstica(K2.racunId)).mail_poskusi === 0, "racun je potrjen, PDF ga ni: brez maila, poskus se ne porabi");
    await dodajPdf(K2.racunId, K2.pdf);
    assert(await cakaj(async () => mailiNa(K2.email).length === 1), "ko PDF prispe, mail gre");

    console.log("\n# 3. Dobropis");
    const K3 = await nov({ vrsta: "dobropis", email: "bor.kupec@primer.si", cents: 1200 });
    assert(await cakaj(async () => mailiNa(K3.email).some((x) => /dobropis/i.test(x.subject))), "dobropis: mail poslan");
    await pocakaj(1000);
    const dm = mailiNa(K3.email).filter((x) => /dobropis/i.test(x.subject));
    assert(dm.length === 1 && /Vaš dobropis \/ Your credit note/.test(dm[0].subject) && /12,00 EUR/.test(dm[0].text) && dm[0].attachments.length === 1 && /^dobropis-/.test(dm[0].attachments[0].filename), "dobropis: svoj mail, znesek brez predznaka, PDF dobropisa", dm[0] && dm[0].subject);

    console.log("\n# 4. Znana napaka Resenda (4xx): ponovitev, na koncu natanko en mail");
    R.napaka = 2;
    const K4 = await nov();
    assert(await cakaj(async () => mailiNa(K4.email).length === 1, 20000), "po dveh zavrnitvah mail vendarle gre");
    await pocakaj(1500);
    const r4 = await vrstica(K4.racunId);
    assert(mailiNa(K4.email).length === 1 && r4.mail_poskusi === 3 && r4.mail_poslano_at !== null && !r4.mail_izid_neznan, "natanko en mail, 3 poskusi", [mailiNa(K4.email).length, r4.mail_poskusi]);

    console.log("\n# 5. Izid neznan (rok Resenda potekel): NI ponovitve, POZOR");
    R.zamik = 1500;
    const K5 = await nov();
    assert(await cakaj(async () => (await vrstica(K5.racunId)).mail_izid_neznan === true, 10000), "mail_izid_neznan = true");
    R.zamik = 0;
    await pocakaj(2500);
    const r5 = await vrstica(K5.racunId);
    assert(mailiNa(K5.email).length === 1 && r5.mail_poskusi === 1 && r5.mail_poslano_at === null, "Resend je mail ob zamiku sprejel enkrat, nobene ponovitve (bi bila kopija brez oznake)", [mailiNa(K5.email).length, r5.mail_poskusi]);
    assert(/POZOR.*izid maila.*neznan/i.test(A.log) && !A.log.includes(K5.email), "POZOR brez e-naslova");

    console.log("\n# 6. Ni potrjen / izbrisan racun");
    const K6a = await nov({ stanje: "izdan" }), K6b = await nov({ email: "izbrisan-1@outly.invalid" });
    await pocakaj(1800);
    assert(mailiNa(K6a.email).length === 0 && mailiNa(K6b.email).length === 0, "racun brez EOR (izdan) in naslov *@outly.invalid: brez maila");
    assert((await vrstica(K6b.racunId)).mail_poskusi >= 8, "izbrisan racun: poskusi izcrpani (se ne ponavlja)", (await vrstica(K6b.racunId)).mail_poskusi);

    console.log("\n# 7. Dva procesa hkrati");
    B = zagon(PORT_B); await cakajStreznik(`http://127.0.0.1:${PORT_B}`);
    const ks = []; for (let i = 0; i < 5; i++) ks.push(await nov());
    assert(await cakaj(async () => ks.every((k) => mailiNa(k.email).length >= 1), 15000), "vseh 5 racunov poslanih");
    await pocakaj(2000);
    assert(ks.every((k) => mailiNa(k.email).length === 1), "vsak racun natanko enkrat (rezervacija v bazi), dva procesa", ks.map((k) => mailiNa(k.email).length));

    console.log("\n# 7b. Proces se ustavi MED klicem Resenda: ob ponovnem zagonu mail NI ponovljen (izid neznan), POZOR");
    await ustavi(A); await ustavi(B); A = null; B = null;
    const C0 = zagon(PORT_A, { RACUN_MAIL_NEZNAN_ALARM_MS: "500" }); await cakajStreznik(`http://127.0.0.1:${PORT_A}`);
    R.zamik = 4000; const prispelo0 = R.prispelo;
    const K7 = await nov();
    assert(await cakaj(async () => R.prispelo > prispelo0 && (await vrstica(K7.racunId)).mail_poskusi === 1, 15000), "rezervacija poskusa zapisana, zahtevek je prispel k Resendu, ta se ne odziva");
    assert((await vrstica(K7.racunId)).mail_izid_neznan === true, "med klicem je mail_izid_neznan ze TRUE (pesimisticno)");
    C0.srv.kill("SIGKILL"); await pocakaj(300);
    R.zamik = 0;
    A = zagon(PORT_A, { RACUN_MAIL_NEZNAN_ALARM_MS: "500" }); await cakajStreznik(`http://127.0.0.1:${PORT_A}`);
    await pocakaj(4500);
    const r7 = await vrstica(K7.racunId);
    assert(mailiNa(K7.email).length === 1 && r7.mail_poskusi === 1 && r7.mail_izid_neznan === true && r7.mail_poslano_at === null, "natanko en mail (Resend ga je sprejel), po zagonu nobene ponovitve", [mailiNa(K7.email).length, r7.mail_poskusi]);
    assert(/POZOR.*neznanim izidom maila/.test(A.log) && !A.log.includes(K7.email), "POZOR (alarm neznanega izida), brez e-naslova");

    console.log("\n# 8. Pot nakupa, webhooka in skena ne poslje racuna (I16)");
    const koda = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8");
    const klici = [...koda.matchAll(/posljiRacunKupcu\(/g)].length;
    const vsa = [...koda.matchAll(/racunKupcuPosljiNeposlane\(/g)].length;
    assert(klici === 2 && vsa === 2, "posljiRacunKupcu: definicija + klic iz pospravljalca; racunKupcuPosljiNeposlane: definicija + klic iz gostPosljiNeposlane", [klici, vsa]);
  } finally {
    await ustavi(A); await ustavi(B);
    jwksServer.close(); resendServer.close(); await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error("IZJEMA", e); process.exit(1); });
