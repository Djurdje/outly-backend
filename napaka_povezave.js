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
module.exports = { jeNapakaPovezave };
