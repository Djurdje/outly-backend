const sentry = require("./sentry");   // Sentry (#87): no-op brez SENTRY_DSN
// Ali je napaka iz baze/poola zacasna tezava povezave (-> 503 + Retry-After) ali programska/podatkovna napaka (-> 500).
// Uporablja requireClubNa v index.js (issue #125); loceno, da jo unit test (_testi/test_napaka_povezave.js) preizkusi brez streznika.
//  - Node omrezne kode (ECONNRESET, ETIMEDOUT, ECONNREFUSED, EPIPE, ENOTFOUND, EAI_AGAIN ...): povezava. Preveri se PRVA, ker
//    ima npr. EPIPE 5 znakov kot SQLSTATE; omrezne kode so brez stevk, SQLSTATE ima vedno vsaj eno.
//  - SQLSTATE (5 znakov): samo razredi 08 (povezava), 53 (premalo sredstev, npr. 53300 too_many_connections) in 57 (poseg
//    operaterja, npr. 57P01 admin_shutdown); vse drugo (40P01 deadlock, 22003, 42P01 ...) je 500.
//  - pg napake brez kode ("timeout exceeded when trying to connect", "Connection terminated unexpectedly", "Query read timeout"):
//    povezava, razen ce je programska napaka (TypeError, ReferenceError, RangeError, SyntaxError).
function jeNapakaPovezave(e) {
  if (!e || e instanceof TypeError || e instanceof ReferenceError || e instanceof RangeError || e instanceof SyntaxError) return false;
  const koda = String(e.code || "");
  if (/^E[A-Z_]+$/.test(koda)) return true;
  if (/^[0-9A-Z]{5}$/.test(koda) && /[0-9]/.test(koda)) return /^(08|53|57)/.test(koda);
  if (koda) return false;
  return /timeout|timed out|connect|terminated|ended|closed/i.test(String(e.message || ""));
}

// Zacasna napaka baze = napaka povezave ALI 55P03 lock_not_available (lock_timeout). skenPool ima lock_timeout (S1, 17. 10. 2026):
// sken, ki med migracijo caka na zaklep tickets, dobi 503 (telefon preklopi na sken brez povezave), ne 500. 55P03 je namenoma
// LOCENO od jeNapakaPovezave: napakaRocnik (asinhroni_rocniki.js) ga se vedno vrne kot 500 (_testi/test_connect_napaka.js S3).
function jeZacasnaNapaka(e) {
  return jeNapakaPovezave(e) || (!!e && e.code === "55P03");
}

// Skupen odgovor za lasten `catch (e)` poti (issue #132, I10): napaka povezave/baze (izcrpan pool, prekinjena povezava, timeout)
// je zacasna tezava streznika -> 503 + Retry-After 5 (odjemalec poskusi znova, sken na vratih preklopi na nacin brez povezave);
// vse drugo (programska/podatkovna napaka) -> 500 s polnim skladom v dnevniku. `kje` je oznaka poti za dnevnik (brez zetonov).
// Odgovor ze poslan: ne pisemo dvojnega, napako samo zapisemo. Isto merilo kot requireClubNa in napakaRocnik.
function odgovoriNaNapako(res, e, kje) {
  const oznaka = kje ? ` (${kje})` : "";
  if (res.headersSent) { console.error(`[napaka] po poslanem odgovoru${oznaka}:`, (e && e.stack) || e); return; }
  if (jeZacasnaNapaka(e)) {
    console.error(`[napaka] zacasna napaka povezave z bazo${oznaka}:`, (e && e.message) || e);
    return res.status(503).set("Retry-After", "5").json({ error: "service_unavailable", message: "Service temporarily unavailable. Please try again." });
  }
  console.error(`[napaka] nepricakovana napaka${oznaka}:`, (e && e.stack) || e);
  sentry.porociNapako(e, kje || "pot", null, res);
  return res.status(500).json({ error: "server_error", message: "Server error." });
}
module.exports = { jeNapakaPovezave, jeZacasnaNapaka, odgovoriNaNapako };
