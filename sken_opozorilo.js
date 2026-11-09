"use strict";
// Opozorilo `sken_ni_pripravljen` (#406, 075, I71): ENA resnica za pogoj + mail Martinu (076).
//  - SQL_SKEN_NEPRIPRAVLJEN: FROM/WHERE fragment, ki ga uporabljata panel (admin_nadzor.js) IN posiljalec maila (nikoli dve kopiji pogoja). Parameter $1 = okno v minutah.
//  - ustvari(dep).krog(): kandidati -> prevzem v `sken_opozorila_poslana` (INSERT ... ON CONFLICT ... RETURNING; kdor dobi vrstico, poslje) -> mail -> poslano_at.
//    Najvec 1 mail na dogodek tudi pri vec procesih in po restartu. Neuspeh (Resend { error }) = ponovitev po premoru, najvec SKEN_OPOZORILO_POSKUSOV.
//  - GLAVNI pool z roki poizvedb (lock_timeout, statement_timeout), NIKOLI skenPool; sken na vratih od delavca ni odvisen. Brez prejemnika ali Resenda: samo POZOR (delavci.pozorRedko).
const SKEN_PRIPRAVLJEN_OKNO_MIN = 120;   // dogodek se zacne v tolikem casu (ali ze tece), seznama za vrata pa ni prenesel nihce v 24 h
const SKEN_OPOZORILO_POSKUSOV = 5;
const PANEL_URL = "https://outly-backend-roy3.onrender.com/admin/";

// $1 = okno (minute). Dogodek mora biti objavljen, klub ne skrit, imeti veljavno vstopnico placanega narocila (guest lista je placano narocilo z vstopnico)
// in nobenega prenosa seznama v 24 h.
const SQL_SKEN_NEPRIPRAVLJEN = `FROM events e JOIN clubs c ON c.id = e.club_id
            WHERE e.status = 'published' AND NOT c.hidden
              AND e.start_at <= NOW() + ($1::int * INTERVAL '1 minute')
              AND e.start_at > NOW() - INTERVAL '7 days'   -- spodnja meja za indeks events_start_idx (brez nje bere vse pretekle dogodke); dogodek, daljsi od 7 dni, ni zajet
              AND COALESCE(e.end_at, e.start_at + INTERVAL '18 hours') > NOW()   -- brez konca kot sken (I25) in seznam dogodkov: zacetek + 18 h
              AND EXISTS (SELECT 1 FROM tickets t JOIN orders o ON o.id = t.order_id
                           WHERE t.event_id = e.id AND t.status = 'valid' AND o.status IN ('paid', 'partially_refunded'))
              AND NOT EXISTS (SELECT 1 FROM sken_prenosi sp WHERE sp.event_id = e.id AND sp.zadnji_prenos > NOW() - INTERVAL '24 hours')`;

function okoljeCelo(env, ime, privzeto, min, max) {
  const v = Number.parseInt(env[ime], 10);
  return Number.isInteger(v) && v >= min && v <= max ? v : privzeto;
}
const ubezi = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cisto = (s, najvec) => String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").replace(/\s+/g, " ").trim().slice(0, najvec);

// Mail Martinu (SL + EN). Samo naslov dogodka, ime kluba in cas (podatki klubov: v HTML ubezani); NOBENIH podatkov kupcev. Noga s firmo se doda v posiljanju (gostResendPosli).
function mailVsebina(x) {
  const naslov = cisto(x.title, 200), klub = cisto(x.club_name, 100);
  const d = new Date(x.start_at);
  const casSl = d.toLocaleString("sl-SI", { timeZone: "Europe/Ljubljana", dateStyle: "full", timeStyle: "short" });
  const casEn = d.toLocaleString("en-GB", { timeZone: "Europe/Ljubljana", dateStyle: "full", timeStyle: "short" });
  const zadeva = `Sken na vratih ni pripravljen / Door scan not ready: ${naslov}`;
  const besedilo = [
    `Sken brez povezave na vratih ni pripravljen: »${naslov}« (${klub}).`, "",
    `Začetek: ${casSl} (ljubljanski čas).`,
    "Noben telefon kluba še ni prenesel seznama vstopnic za sken brez povezave (zadnjih 24 h). Če ob izpadu omrežja na vratih ne bo povezave, sken ne bo deloval.",
    "Kaj naj narediš: sporoči klubu, naj na dogodku odpre skener (Outly → Poslovni → Skener), ko ima internet; s tem se seznam prenese na telefon.",
    `Panel: ${PANEL_URL}`, "",
    "----------------------------------------", "",
    `Offline door scan is not ready: "${naslov}" (${klub}).`, "",
    `Starts: ${casEn} (Ljubljana time).`,
    "No club phone has downloaded the ticket list for offline scanning yet (last 24 h). If the network drops at the door, scanning will not work.",
    "What to do: tell the club to open the scanner (Outly → Business → Scanner) while they still have internet; this downloads the list to the phone.",
    `Panel: ${PANEL_URL}`,
  ].join("\n");
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;line-height:1.5;color:#111">
    <h2 style="color:#b25e00;margin:0 0 8px">Sken na vratih ni pripravljen</h2>
    <p><b>${ubezi(naslov)}</b> (${ubezi(klub)})<br>Začetek: ${ubezi(casSl)} (ljubljanski čas)</p>
    <p>Noben telefon kluba še ni prenesel seznama vstopnic za sken brez povezave (zadnjih 24 h). Če ob izpadu omrežja na vratih ne bo povezave, sken ne bo deloval.</p>
    <p><b>Kaj naj narediš:</b> sporoči klubu, naj na dogodku odpre skener (Outly → Poslovni → Skener), ko ima internet; s tem se seznam prenese na telefon.</p>
    <p>Panel: <a href="${PANEL_URL}">${PANEL_URL}</a></p>
    <hr style="border:0;border-top:1px solid #ccc;margin:20px 0">
    <h2 style="color:#b25e00;margin:0 0 8px">Offline door scan is not ready</h2>
    <p><b>${ubezi(naslov)}</b> (${ubezi(klub)})<br>Starts: ${ubezi(casEn)} (Ljubljana time)</p>
    <p>No club phone has downloaded the ticket list for offline scanning yet (last 24 h). If the network drops at the door, scanning will not work.</p>
    <p><b>What to do:</b> tell the club to open the scanner (Outly → Business → Scanner) while they still have internet; this downloads the list to the phone.</p>
    <p>Panel: <a href="${PANEL_URL}">${PANEL_URL}</a></p></div>`;
  return { zadeva, besedilo, html };
}

function ustvari(dep) {
  const { pool, delavci } = dep;
  const env = dep.env || process.env;
  const log = dep.log || console;
  const PERIODA_MS = okoljeCelo(env, "SKEN_OPOZORILO_MS", 300000, 0, 3600000);          // 0 = izklop
  const PREMOR_MS = okoljeCelo(env, "SKEN_OPOZORILO_PREMOR_MS", 120000, 0, 3600000);     // premor pred ponovnim poskusom istega dogodka
  const PAKET = 20;                                                                       // najvec dogodkov na krog
  const prejemniki = () => String(env.OPOZORILA_MAIL || env.AGENT_NUJNO_MAIL || "").split(",").map((x) => x.trim()).filter((x) => /^[^@\s]+@[^@\s]+$/.test(x));

  // Kratka transakcija z roki (kot skenPrenosZabelezi, I71): zaklep ali pocasna baza krog le preskoci.
  async function vTx(fn) {
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL lock_timeout = '500ms'; SET LOCAL statement_timeout = '3000ms'");
      const r = await fn(c);
      await c.query("COMMIT");
      return r;
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
    finally { c.release(); }
  }

  async function krog() {
    if (pool.waitingCount > 0) return { preskoceno: true };   // pool caka na povezavo: nakupi imajo prednost
    const kand = (await vTx((c) => c.query(
      `SELECT e.id, e.title, c.name AS club_name, e.start_at ${SQL_SKEN_NEPRIPRAVLJEN}
          AND NOT EXISTS (SELECT 1 FROM sken_opozorila_poslana s WHERE s.event_id = e.id AND (s.poslano_at IS NOT NULL OR s.poskusi >= $3))
        ORDER BY e.start_at, e.id LIMIT $2`, [SKEN_PRIPRAVLJEN_OKNO_MIN, PAKET, SKEN_OPOZORILO_POSKUSOV]))).rows;
    if (!kand.length) return { poslano: 0 };
    const naslovi = prejemniki();
    if (!naslovi.length || !dep.imaResend()) {
      delavci.pozorRedko("sken-opozorilo:brez-naslova", `[sken-opozorilo] POZOR: ${kand.length} dogodkov ima vrata brez pripravljenega skena brez povezave, a maila ni mogoce poslati (OPOZORILA_MAIL / AGENT_NUJNO_MAIL ali Resend ni nastavljen); preveri opozorila v panelu`, log);
      return { poslano: 0, brezNaslova: true };
    }
    let poslano = 0;
    for (const x of kand) {
      const k = await vTx((c) => c.query(
        `INSERT INTO sken_opozorila_poslana AS s (event_id) VALUES ($1)
         ON CONFLICT (event_id) DO UPDATE SET poskusi = s.poskusi + 1, prevzeto_at = NOW()
          WHERE s.poslano_at IS NULL AND s.poskusi < $2 AND s.prevzeto_at < NOW() - ($3::int * INTERVAL '1 millisecond')
         RETURNING s.poskusi`, [x.id, SKEN_OPOZORILO_POSKUSOV, PREMOR_MS]));
      if (!k.rows.length) continue;   // drug proces je prevzel ali je ze poslano / premor se ni potekel
      const poskus = k.rows[0].poskusi;
      const m = mailVsebina(x);
      let r;
      try { r = await dep.posljiMail({ to: naslovi, subject: m.zadeva, html: m.html, text: m.besedilo }); }
      catch (e) { r = { error: { message: e && e.message } }; }
      if (r && r.error) {   // Resend ob napaki NE vrze, vrne { error }; vrstica ostane (poskusi), ponovitev po premoru
        log.error(`[sken-opozorilo] mail za dogodek ${x.id} ni potrjen (poskus ${poskus}/${SKEN_OPOZORILO_POSKUSOV}): ${String(r.error.name || "")} ${String(r.error.message || "").slice(0, 100)}`);
        if (poskus >= SKEN_OPOZORILO_POSKUSOV) delavci.pozorRedko(`sken-opozorilo:izcrpano:${x.id}`, `[sken-opozorilo] POZOR: mail Martinu za dogodek ${x.id} ni uspel ${SKEN_OPOZORILO_POSKUSOV}x; vrata brez skena brez povezave, preveri Resend in panel`, log);
        continue;
      }
      for (let i = 0; ; i++) {
        try { await pool.query("UPDATE sken_opozorila_poslana SET poslano_at = NOW() WHERE event_id = $1", [x.id]); break; }
        catch (e) { if (i >= 2) { log.error(`[sken-opozorilo] mail za dogodek ${x.id} je poslan, zapisa ni bilo mogoce narediti (${e && e.message}); po premoru lahko pride se enkrat`); break; } await new Promise((res) => setTimeout(res, 200)); }
      }
      poslano++;
      log.log(`[sken-opozorilo] mail Martinu poslan za dogodek ${x.id}`);
    }
    return { poslano };
  }

  let tece = false, casovnik = null;
  function zazeni() {
    if (PERIODA_MS <= 0) return null;
    const utrip = delavci.registriraj("sken_opozorilo", { periodaMs: PERIODA_MS, zamikMs: PERIODA_MS });
    casovnik = setInterval(() => {
      if (tece) return;   // obvisel krog ne sme sprozati novih (S1, I70)
      tece = true;
      const k = utrip.zacetek();
      krog().catch((e) => log.error("[sken-opozorilo] krog ni uspel:", e && e.message)).finally(() => { k.konec(); tece = false; });
    }, PERIODA_MS);
    if (casovnik.unref) casovnik.unref();
    return casovnik;
  }
  return { krog, zazeni, mailVsebina, prejemniki };
}

module.exports = { SKEN_PRIPRAVLJEN_OKNO_MIN, SKEN_OPOZORILO_POSKUSOV, SQL_SKEN_NEPRIPRAVLJEN, mailVsebina, ustvari };
