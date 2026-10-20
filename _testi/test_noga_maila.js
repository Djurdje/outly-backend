#!/usr/bin/env node
/**
 * Noga maila (ZVPot-1 7(1) drugi stavek; pravnik outly-hq/pravno/2026-10-20-potrdilo-nakupa-kratko.md, tabela vrstica 5): VSAK mail uporabniku nosi
 * celotno ime firme in sedez posiljatelja. Staticna preverba index.js (brez baze in streznika): vsak klic resend.emails.send gre skozi nogaMaila,
 * razen internega maila ekipi. Vsebino noge v posameznih vrstah mailov preverjajo test_potrdilo_kupcu, test_gost, test_prenos_gost, test_vracila
 * in test_vracilo_iz_stripa (»noga s firmo in sedezem v vseh … mailih«).
 *   node _testi/test_noga_maila.js
 */
const fs = require("fs");
const path = require("path");
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const koda = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8");
const FIRMA = "NEXT DIMENSIONS, družba za marketing, d.o.o.", SEDEZ = "Trebče 81, 3256 Bistrica ob Sotli";

console.log("\n# Noga: konstanta in funkcija");
assert(koda.includes(`const FIRMA_PLATFORME = "${FIRMA}", SEDEZ_PLATFORME = "${SEDEZ}";`), "FIRMA_PLATFORME in SEDEZ_PLATFORME: celotno ime firme in sedez");
assert(/const NOGA_MAILA = `Pošiljatelj \/ Sender: \$\{FIRMA_PLATFORME\}, \$\{SEDEZ_PLATFORME\}`;/.test(koda), "NOGA_MAILA: »Pošiljatelj / Sender: firma, sedež«");
assert(/const POSREDNIK_VRSTICA = `\$\{FIRMA_PLATFORME\}, \$\{SEDEZ_PLATFORME\}, luka@outly\.si`;/.test(koda), "POSREDNIK_VRSTICA iz iste konstante (ena resnica)");
const telo = (ime) => { const i = koda.indexOf(`async function ${ime}(`); return i < 0 ? "" : koda.slice(i, koda.indexOf("\n}\n", i)); };
assert(/\(\{ html, text \} = nogaMaila\(\{ html, text \}\)\)/.test(telo("gostResendPosli")), "gostResendPosli (vsi maili kupcem, gostom, prejemnikom, vracila, spori) doda nogo pred klicem Resenda");

console.log("\n# Vsak klic resend.emails.send");
const zacetki = [...koda.matchAll(/resend\.emails\.send\(\{/g)].map((m) => m.index);
const klici = zacetki.map((z, i) => {   // blok klica: do naslednjega klica ali najvec 1500 znakov
  const blok = koda.slice(z, Math.min(z + 1500, zacetki[i + 1] || Infinity));
  const funkcija = ((koda.slice(0, z).match(/function (\w+)\(/g) || []).pop() || "?").replace(/^function |\($/g, "");
  return { funkcija, blok };
});
assert(klici.length >= 4, "najdeni vsi klici resend.emails.send", klici.length);
for (const k of klici) {
  const interno = /to: ekipa/.test(k.blok);
  const zNogo = /nogaMaila\(/.test(k.blok) || k.funkcija === "gostResendPosli";
  assert(interno || zNogo, `${k.funkcija}: ${interno ? "interni mail ekipi (brez noge)" : "z nogo"}`, k.blok.slice(0, 160));
}
console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
process.exit(fail ? 1 : 0);
