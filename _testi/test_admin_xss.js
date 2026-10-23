#!/usr/bin/env node
/**
 * Admin panel, zavihek »Vračila in spori« (#233) in njegovi trije števci na pregledu: podatki iz API-ja NE smejo v HTML
 * (XSS: admin seja je v localStorage, opis napake Stripa in ime dogodka sta tuja vnosa). Zagon (čisti Node, brez baze in brskalnika):
 *   node _testi/test_admin_xss.js
 *
 * Statični del: iz `admin/index.html` izluščimo odsek »vračila in spori« in preverimo, da nima `innerHTML`/`outerHTML`/
 * `insertAdjacentHTML`/`document.write`/`srcdoc`/... razen praznjenja (`innerHTML = ""`); da je vsak klic `/admin/api/refunds` in
 * `/admin/api/disputes` v tem odseku (zavihek se ne more neopazno preseliti iz pokritega območja); da števec `kosPozor` število
 * vedno spremeni v Number in da so njegovi drugi/tretji argumenti vedno literali.
 * Izvajalni del: odsek zaženemo v minimalnem lažnem DOM-u (ustvarjeni elementi, `innerHTML` setter beleži), v API odgovore
 * vstavimo `<img src=x onerror=...>` in preverimo, da vsebina konča kot besedilo (text node), ne kot element.
 * Vsak korak, ki ga ne najde, PADE (ne preskoči).
 * Odsek 6 (U3, 23. 10. 2026): zavihek Uporabniki. Vrstica prek h(), brez onclick/onchange nizov; izbira vloge ne kliče API-ja, PATCH šele po potrdi()
 * (vpis e-naslova + obvezen razlog za admin/backup in odvzem vloge admin); preklic vrne izbiro.
 */
const fs = require("fs");
const path = require("path");

let ok = 0, fail = 0;
function assert(c, ime, podrobnost) {
  if (c) { ok++; console.log("  ✓ " + ime); } else { fail++; console.log("  ✗ " + ime + (podrobnost !== undefined ? " " + JSON.stringify(podrobnost) : "")); }
}
function mora(c, sporocilo) { if (!c) { console.log("  ✗ " + sporocilo); console.log(`\nSkupaj: ${ok} OK, ${fail + 1} napak`); process.exit(1); } }

const html = fs.readFileSync(path.join(__dirname, "..", "admin", "index.html"), "utf8");
const sc0 = html.indexOf("<script>"), sc1 = html.lastIndexOf("</script>");
mora(sc0 > 0 && sc1 > sc0, "admin/index.html: skripta ni najdena");
const skripta = html.slice(sc0 + 8, sc1);

// --- odsek zavihka ---
const ZAC = "// ---------- vračila in spori", KON = "// ---------- zagon";
const iz = skripta.indexOf(ZAC), ik = skripta.indexOf(KON);
mora(iz >= 0 && ik > iz, `odsek »${ZAC}« … »${KON}« ni najden (preimenovan komentar? popravi test, ne preskoči)`);
const odsek = skripta.slice(iz, ik);
console.log(`Odsek zavihka: ${odsek.split("\n").length} vrstic`);
for (const f of ["naloziVracila", "naloziVracilaSeznam", "naloziSpore", "vTabela", "vRetry", "znackaIz"]) {
  mora(new RegExp(`function ${f}\\(`).test(odsek), `funkcija ${f} ni v odseku zavihka`);
}
mora(odsek.includes("/admin/api/refunds") && odsek.includes("/admin/api/disputes"), "odsek ne kliče /admin/api/refunds in /admin/api/disputes");

// --- 1. statično: nevarni ponori ---
const NEVARNO = /\.(innerHTML|outerHTML)\b|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|\.srcdoc\b|createContextualFragment|DOMParser|\beval\s*\(|new\s+Function\b|setAttribute\(\s*["'`]on/g;
const kazni = [];
for (const m of odsek.matchAll(NEVARNO)) {
  const rep = odsek.slice(m.index, m.index + 60);
  if (/^\.innerHTML\s*=\s*(""|'')\s*[;,)}]/.test(rep)) continue;   // praznjenje
  kazni.push(rep.split("\n")[0]);
}
assert(kazni.length === 0, "odsek »vračila in spori« nima innerHTML/outerHTML/insertAdjacentHTML/document.write s podatki (razen praznjenja)", kazni);

// --- 2. statično: vsi klici obeh API poti so v odseku ---
const zunaj = skripta.slice(0, iz) + skripta.slice(ik);
assert(!zunaj.includes("/admin/api/refunds") && !zunaj.includes("/admin/api/disputes"), "klici /admin/api/refunds in /admin/api/disputes so samo v pokritem odseku");

// --- 3. trije števci na pregledu (kosPozor) ---
const mk = skripta.match(/const kosPozor = [^\n]*\n/);
mora(mk, "kosPozor ni najden v naloziPregled");
assert(/Number\(n\)\s*\|\|\s*0/.test(mk[0]) && /<b>\$\{x\}<\/b>/.test(mk[0]), "kosPozor: število gre skozi Number(n) || 0 in v HTML samo kot ${x}", mk[0]);
const klici = [...skripta.matchAll(/kosPozor\((.*?)\)(?:\s*\+|;)/g)];
mora(klici.length === 3, `pričakovani trije klici kosPozor (števci: vračila, spori, povrnitve), najdeno ${klici.length}`);
assert(klici.every(k => /^[\w.]+,\s*"[^"$`<>]*",\s*"(pozor|opoz)"$/.test(k[1])), "kosPozor: 2. in 3. argument sta vedno literala (podatek gre samo kot 1. argument)", klici.map(k => k[1]));
const kosPozor = new Function(mk[0].replace(/^const kosPozor = /, "return ").replace(/;\s*$/, ""))();
const zlo = '<img src=x onerror="alert(1)">';
for (const v of [zlo, "1<script>", "NaN", null, undefined, { toString: () => zlo }, [zlo]]) {
  const izh = kosPozor(v, "ime", "pozor");
  assert(!/[<>]img|<script|onerror/.test(izh.replace(/<\/?(div|b|span)[^>]*>/g, "")), "kosPozor(" + JSON.stringify(v) + "): izhod nima podatka kot oznake", izh);
}
assert(/\$\("nVracil"\)\.textContent\s*=/.test(skripta) && !/\$\("nVracil"\)\.innerHTML/.test(skripta), "značka »Vračila in spori« v meniju: textContent");

// --- 4. izvajalni del: lažni DOM ---
class Besedilo { constructor(t) { this.nodeType = 3; this.data = String(t); } get textContent() { return this.data; } }
const innerHTMLZapisi = [];
class El {
  constructor(tag) { this.nodeType = 1; this.tagName = String(tag).toLowerCase(); this.attrs = {}; this.children = []; this.className = ""; this.onclick = null; this.value = ""; this.disabled = false; this._tc = null; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  append(...o) { for (const x of o) this.children.push(typeof x === "string" ? new Besedilo(x) : x); }
  appendChild(x) { this.children.push(x); return x; }
  replaceChildren(...o) { this.children = []; this.append(...o.flat()); }
  get classList() { const s = this; return { add() {}, remove() {}, toggle() {} }; }
  set textContent(t) { this.children = [new Besedilo(t)]; }
  get textContent() { return this.children.map(c => c.textContent).join(""); }
  set innerHTML(v) { innerHTMLZapisi.push(v); this.children = []; }
  get innerHTML() { innerHTMLZapisi.push("<branje>"); return ""; }
}
const dok = { createElement: (t) => new El(t), createTextNode: (t) => new Besedilo(t) };
function sprehod(el, f) { f(el); for (const c of el.children || []) sprehod(c, f); }

const mh = skripta.match(/function h\(tag, lastnosti, \.\.\.otroci\) \{[\s\S]*?\n\}\n/);
mora(mh, "funkcija h() ni najdena");
const md = skripta.match(/function datum\(s\) \{[^\n]*\}\n/);
mora(md, "funkcija datum() ni najdena");

const elementi = {};
const $ = (id) => (elementi[id] = elementi[id] || new El("div"));
let odgovori = {}, obvestila = [];
const klic = async (metoda, pot) => {
  const k = Object.keys(odgovori).find(x => pot.startsWith(x));
  mora(k, "nepričakovan klic API-ja iz zavihka: " + metoda + " " + pot);
  return JSON.parse(JSON.stringify(odgovori[k]));
};
const varno = async (fn) => { await fn(); };   // namenoma brez ujetja: napaka v risanju pade test
const obvesti = (b) => obvestila.push(b);
const naloziPregled = () => {};
const zaganjalnik = new Function("document", "$", "klic", "varno", "obvesti", "naloziPregled",
  `${md[0]}\n${mh[0]}\n${odsek}\nreturn { naloziVracilaSeznam, naloziSpore };`);
const { naloziVracilaSeznam, naloziSpore } = zaganjalnik(dok, $, klic, varno, obvesti, naloziPregled);

const ZLO = ['<img src=x onerror=alert("pub")>', "<script>alert('naslov')</script>", '"><svg onload=alert(1)>', "</td><img src=x onerror=1>"];
const vracilo = (id, polja) => ({ id, order_id: 100 + id, public_ref: ZLO[0], event_id: 7, event_title: ZLO[1], reason: ZLO[2], state: "ni_uspelo", amount_cents: 2000, currency: "eur",
  attempts: 1, error: ZLO[3], no_stripe: false, stripe_refund_id: null, fee_refund_cents: 141, created_at: "2026-10-12T10:00:00Z", next_attempt_at: null, done_at: null, ...polja });
const spor = (id, polja) => ({ id, order_id: 5, public_ref: ZLO[0], event_title: ZLO[1], club_id: 1, state: ZLO[2], reason: ZLO[3], amount_cents: 2000, currency: "eur", evidence_due_at: null,
  created_at: "2026-10-12T10:00:00Z", closed_at: null, recovery_state: "ni_uspelo", recovery_wanted_cents: 2000, recovered_cents: 0, dispute_fee_cents: 1500, recovery_error: ZLO[3], ...polja });

function pregled(korenski) {
  const najdeno = { elementi: [], besedila: [] };
  sprehod(korenski, (n) => {
    if (n.nodeType === 3) { najdeno.besedila.push(n.data); return; }
    najdeno.elementi.push(n.tagName);
    for (const k of Object.keys(n.attrs)) if (/^on/i.test(k)) najdeno.elementi.push("atribut:" + k);
  });
  return najdeno;
}
const DOVOLJENI = new Set(["div", "table", "thead", "tbody", "tr", "th", "td", "b", "span", "button"]);

(async () => {
  // vračila
  $("v_filter").value = "all"; $("s_filter").value = "all";
  odgovori = { "/admin/api/refunds": { counts: { ni_uspelo: 1, [ZLO[0]]: 3 }, items: [vracilo(1, {}), vracilo(2, { state: ZLO[1] }), vracilo(3, { state: "rocno", error: null, stripe_state: ZLO[2] })] }, "/admin/api/disputes": { items: [spor("dp_1", {}), spor("dp_2", { recovery_state: null, public_ref: null })] } };
  await naloziVracilaSeznam();
  await naloziSpore();
  const tabV = pregled($("v_tabela")), tabS = pregled($("s_tabela")), stev = pregled($("v_stevci"));
  for (const [ime, p] of [["vračila", tabV], ["spori", tabS], ["števci stanj", stev]]) {
    assert(p.elementi.length > 0, `izvajalno: ${ime} narisana (${p.elementi.length} elementov)`);
    assert(p.elementi.every(t => DOVOLJENI.has(t)), `izvajalno: ${ime}: nobenega elementa iz podatkov (img/script/svg), atributov on*`, [...new Set(p.elementi)]);
  }
  const besedila = [...tabV.besedila, ...tabS.besedila].join("\n");
  for (const z of ZLO) assert(besedila.includes(z), "izvajalno: niz iz podatkov konča kot besedilo: " + z);
  assert($("v_stevci").children.length === 1 && stev.besedila.join("") === "ni uspelo 1", "izvajalno: števci stanj: samo znana stanja iz tabele, število kot besedilo (ključ iz podatkov ne pride na zaslon)", stev.besedila);
  assert(innerHTMLZapisi.every(v => v === ""), "izvajalno: innerHTML je bil samo praznjen (ne beremo, ne pišemo podatkov)", innerHTMLZapisi);

  // gumb »Poskusi znova« (logika iz vracila_stripe.js ponovi(); ostane usklajena z backendom)
  const gumbov = (korenski) => { let n = 0; sprehod(korenski, (e) => { if (e.nodeType === 1 && e.tagName === "button") n++; }); return n; };
  const razlaga = (korenski) => korenski.textContent.includes("vrni ročno v Stripu");
  const primeri = [
    ["ni_uspelo", "failed", false], ["ni_uspelo", "canceled", false], ["ni_uspelo", "requires_action", true], ["potrditev", "requires_action", null], ["rocno", "failed", false], ["rocno", "canceled", false],
    ["ni_uspelo", null, true], ["rocno", null, true], ["ni_uspelo", "pending", true], ["rocno", "succeeded", true], ["ni_uspelo", undefined, true],
    ["opravljeno", "succeeded", null], ["opravljeno", "failed", null], ["potrditev", "pending", null], ["caka", null, null],
  ];
  odgovori = { "/admin/api/refunds": { counts: {}, items: primeri.map((p, i) => vracilo(i + 1, { state: p[0], stripe_state: p[1], public_ref: "R" + i, error: null })) }, "/admin/api/disputes": { items: [] } };
  await naloziVracilaSeznam();
  const trs = [];
  sprehod($("v_tabela"), (e) => { if (e.nodeType === 1 && e.tagName === "tr" && e.children.some(c => c.tagName === "td")) trs.push(e); });
  assert(trs.length === primeri.length, "gumb: narisanih vrstic", [trs.length, primeri.length]);
  primeri.forEach((p, i) => {
    const zadnja = trs[i].children[trs[i].children.length - 1];
    const g = gumbov(zadnja), r = razlaga(zadnja);
    const pricakovano = p[2] === true ? [1, false] : p[2] === false ? [0, true] : [0, false];
    assert(g === pricakovano[0] && r === pricakovano[1], `gumb: stanje ${p[0]}, stripe_state ${p[1]} -> ${p[2] === true ? "gumb »Poskusi znova«" : p[2] === false ? "razlaga namesto gumba (retry bi bil 409)" : "nič"}`, [g, r]);
  });

  // spori: gumb samo pri povrnitvi ni_uspelo / rocno (ponoviSpor nima dodatne zavrnitve → brez stripe_state)
  odgovori = { "/admin/api/refunds": { counts: {}, items: [] }, "/admin/api/disputes": { items: ["ni_uspelo", "rocno", "caka", "opravljeno", null].map((s, i) => spor("dp_" + i, { recovery_state: s })) } };
  await naloziSpore();
  const trsS = [];
  sprehod($("s_tabela"), (e) => { if (e.nodeType === 1 && e.tagName === "tr" && e.children.some(c => c.tagName === "td")) trsS.push(e); });
  assert(trsS.map(t => gumbov(t.children[t.children.length - 1])).join() === "1,1,0,0,0", "spori: gumb samo pri povrnitvi ni_uspelo/rocno", trsS.map(t => gumbov(t)));

  // --- 5. moduli panela (faza 1, 21. 10. 2026: admin/dialog.js, admin/dogodki.js) in brez window.confirm ---
  for (const ime of ["dialog.js", "dogodki.js"]) {
    const kod = fs.readFileSync(path.join(__dirname, "..", "admin", ime), "utf8");
    const k5 = [];
    for (const m of kod.matchAll(NEVARNO)) {
      const rep = kod.slice(m.index, m.index + 60);
      if (/^\.innerHTML\s*=\s*(""|'')\s*[;,)}]/.test(rep)) continue;
      k5.push(rep.split("\n")[0]);
    }
    assert(k5.length === 0, `admin/${ime}: brez innerHTML/outerHTML/insertAdjacentHTML/eval s podatki`, k5);
    assert(!/\bconfirm\s*\(/.test(kod), `admin/${ime}: brez window.confirm (blokirajo ga orodja; panel ima svoje okno)`);
  }
  assert(!/\bconfirm\s*\(/.test(skripta), "admin/index.html: brez window.confirm (vse potrditve prek potrdi() iz dialog.js)");
  assert(/<script src="dialog\.js"><\/script>\s*<script src="dogodki\.js"><\/script>\s*<script>/.test(html), "moduli se naložijo pred glavno skripto");
  // dialog.js: vsebina iz podatkov gre v DOM kot besedilo (izvajalno, lažni DOM)
  {
    const kod = fs.readFileSync(path.join(__dirname, "..", "admin", "dialog.js"), "utf8");
    const body = new El("body"); body.classList = { add() {}, remove() {} };
    const okno = { potrdi: null };
    const docD = { createElement: (t) => new El(t), createTextNode: (t) => new Besedilo(t), body, activeElement: null, addEventListener() {}, removeEventListener() {} };
    El.prototype.focus = function () {}; El.prototype.remove = function () {}; El.prototype.querySelectorAll = function () { return []; };
    Object.defineProperty(El.prototype, "isConnected", { get() { return true; }, configurable: true });
    new Function("window", "document", kod)(okno, docD);
    mora(typeof okno.potrdi === "function", "dialog.js ne izvozi window.potrdi");
    okno.potrdi({ naslov: ZLO[1], vsebina: ZLO[0], potrdiBesedilo: ZLO[2], vpis: "ODPOVEJ", razlog: "obvezen" });
    const p5 = pregled(body);
    assert(p5.elementi.every(t => new Set(["body", "div", "h3", "label", "input", "textarea", "button"]).has(t)), "dialog.js: nizi iz podatkov ne postanejo elementi", [...new Set(p5.elementi)]);
    for (const z of [ZLO[0], ZLO[1], ZLO[2]]) assert(p5.besedila.includes(z), "dialog.js: niz konča kot besedilo: " + z);
    // N5: vpisno polje z e-naslovom (vsebuje @): tipkovnica za e-naslove in brez samodejnih velikih črk; sicer kot prej (velike črke)
    const vpisnaPolja = () => { const r = []; sprehod(body, (e) => { if (e.nodeType === 1 && e.tagName === "input") r.push(e); }); return r; };
    let polja = vpisnaPolja();
    assert(polja.length === 1 && polja[0].attrs.autocapitalize === "characters" && polja[0].attrs.inputmode === undefined, "dialog.js: vpis ODPOVEJ: autocapitalize=characters, brez inputmode", polja.map(x => x.attrs));
    okno.potrdi({ naslov: "x", vsebina: "y", vpis: "ana@primer.si" });
    polja = vpisnaPolja();
    const zadnje = polja[polja.length - 1];
    assert(zadnje && zadnje.attrs.inputmode === "email" && zadnje.attrs.autocapitalize === "off" && zadnje.attrs.autocomplete === "off", "dialog.js: vpis e-naslova: inputmode=email, autocapitalize=off", zadnje && zadnje.attrs);
  }

  // N3: h() nikoli ne nastavi on* atributa iz niza (setAttribute("onclick", "...")); funkcija gre kot lastnost
  {
    const hh = new Function("document", mh[0] + "\nreturn h;")(dok);
    const gumb = hh("button", { onclick: "alert(1)", onmouseover: "alert(2)", onChange: "alert(3)", "data-x": "ok" }, "t");
    assert(!Object.keys(gumb.attrs).some(k => /^on/i.test(k)) && gumb.onclick === null && gumb.attrs["data-x"] === "ok", "h(): on* z nizom ne postane atribut ne lastnost", gumb.attrs);
    const f = () => 1;
    const gumb2 = hh("button", { onclick: f, class: "a" }, "t");
    assert(gumb2.onclick === f && gumb2.className === "a" && !Object.keys(gumb2.attrs).some(k => /^on/i.test(k)), "h(): on* s funkcijo je lastnost");
  }

  // --- 6. zavihek Uporabniki (U3, 23. 10. 2026): vrstica prek h(), sprememba vloge samo prek potrdi(), brez onclick/onchange nizov ---
  {
    const U0 = "// ---------- uporabniki", U1 = "// ---------- guest lists";
    const iu = skripta.indexOf(U0), ik2 = skripta.indexOf(U1);
    mora(iu >= 0 && ik2 > iu, `odsek »${U0}« … »${U1}« ni najden (preimenovan komentar? popravi test, ne preskoči)`);
    const odsekU = skripta.slice(iu, ik2);
    for (const f of ["naloziUporabnike", "uVrstica", "uSpremeniVlogo", "uOdkleni", "uPotrdi"]) mora(new RegExp(`function ${f}\\(`).test(odsekU), `funkcija ${f} ni v odseku Uporabniki`);
    const kU = [];
    for (const m of odsekU.matchAll(NEVARNO)) { const rep = odsekU.slice(m.index, m.index + 60); if (/^\.innerHTML\s*=\s*(""|'')\s*[;,)}]/.test(rep)) continue; kU.push(rep.split("\n")[0]); }
    assert(kU.length === 0, "odsek Uporabniki: brez innerHTML/outerHTML/insertAdjacentHTML/eval s podatki", kU);
    assert(!/\bon(click|change|input|keydown)\s*=\s*["'`]/i.test(odsekU), "odsek Uporabniki: brez onclick=\"...\" / onchange=\"...\" atributov v nizih");
    assert(!/\btabela\(/.test(odsekU), "odsek Uporabniki: ne rabi tabela() (ta piše innerHTML iz nizov)");
    assert(!html.includes('onchange="uVloga') && !/\buVloga\(/.test(html), "nikjer v panelu ni več takojšnje spremembe vloge (onchange=\"uVloga...\")");
    const fnSprememba = odsekU.slice(odsekU.indexOf("async function uSpremeniVlogo("), odsekU.indexOf("async function uOdkleni("));
    assert(fnSprememba.includes("await potrdi(") && fnSprememba.indexOf("await potrdi(") < fnSprememba.indexOf('klic("PATCH"'), "uSpremeniVlogo: PATCH šele po potrdi()");
    assert((odsekU.match(/role:/g) || []).length === 1 && fnSprememba.includes("role: potem"), "vloga se pošlje samo iz uSpremeniVlogo (za potrdi())");
    assert(/vpis:\s*stroga\s*\?\s*\(?x\.email/.test(fnSprememba) && /razlog:\s*stroga\s*\?\s*"obvezen"\s*:\s*"neobvezen"/.test(fnSprememba), "stroga sprememba: vpis e-naslova + obvezen razlog; sicer neobvezen razlog");

    const mc = skripta.match(/function cel\(n\) \{[^\n]*\}/);
    mora(mc, "funkcija cel() ni najdena");
    const potrdiKlici = [], apiKlici = [];
    let potrdiOdgovor = null;
    const potrdiStub = async (o) => { potrdiKlici.push(o); return potrdiOdgovor; };
    const klicU = async (metoda, pot, telo) => {
      apiKlici.push([metoda, pot, telo]);
      if (metoda === "GET") return JSON.parse(JSON.stringify(odgovoriU));
      return { email: "a@b.si", role: telo && telo.role };
    };
    const innerPred = innerHTMLZapisi.length;
    let odgovoriU = [];
    const zU = new Function("document", "$", "klic", "varno", "obvesti", "naloziPregled", "potrdi",
      `${md[0]}\n${mh[0]}\n${mc[0]}\n${odsekU}\nreturn { naloziUporabnike };`);
    const { naloziUporabnike } = zU(dok, $, klicU, varno, obvesti, naloziPregled, potrdiStub);
    const uporabnik = (id, vloga, polja) => ({ id, email: ZLO[0], username: ZLO[1], role: vloga, email_verified: false, phone: ZLO[2], country: ZLO[3], locked_until: "2099-01-01T00:00:00Z",
      failed_login_count: 3, club_count: 1, created_at: "2026-10-12T10:00:00Z", onboarded_at: null, ...polja });
    odgovoriU = [uporabnik(1, "user"), uporabnik(2, "admin", { email_verified: true, locked_until: null }), uporabnik(3, "business", { email: "poste@outly.si", username: "poste" })];
    $("uIsci").value = "";
    await naloziUporabnike();
    const pU = pregled($("uTabela"));
    assert(pU.elementi.length > 0, `izvajalno: Uporabniki narisani (${pU.elementi.length} elementov)`);
    assert(pU.elementi.every(t => new Set(["table", "thead", "tbody", "tr", "th", "td", "div", "span", "select", "option", "button"]).has(t)), "izvajalno: Uporabniki: nobenega elementa iz podatkov (img/script/svg), atributov on*", [...new Set(pU.elementi)]);
    for (const z of ZLO) assert(pU.besedila.includes(z), "izvajalno: Uporabniki: niz iz podatkov konča kot besedilo: " + z);
    assert(innerHTMLZapisi.length === innerPred || innerHTMLZapisi.slice(innerPred).every(v => v === ""), "izvajalno: Uporabniki: innerHTML ni bil uporabljen za podatke");
    assert(apiKlici.length === 1 && apiKlici[0][0] === "GET", "izvajalno: izris samo bere (en GET)", apiKlici);

    const vrstice = [];
    sprehod($("uTabela"), (e) => { if (e.nodeType === 1 && e.tagName === "tr" && e.children.some(c => c.tagName === "td")) vrstice.push(e); });
    assert(vrstice.length === 3, "izvajalno: Uporabniki: tri vrstice", vrstice.length);
    const iz = (vrstica, tag, besedilo) => { let r = null; sprehod(vrstica, (e) => { if (!r && e.nodeType === 1 && e.tagName === tag && (!besedilo || e.textContent === besedilo)) r = e; }); return r; };
    const izbira = (v) => iz(v, "select"), gumbVloga = (v) => iz(v, "button", "Spremeni vlogo");
    assert(vrstice.every(v => izbira(v) && gumbVloga(v) && gumbVloga(v).disabled === true), "izvajalno: gumb »Spremeni vlogo« je onemogočen, dokler izbira ni drugačna od trenutne vloge");
    assert(vrstice.map(v => izbira(v).value).join() === "user,admin,business", "izvajalno: izbira kaže trenutno vlogo", vrstice.map(v => izbira(v).value));
    assert(vrstice.every(v => !Object.keys(izbira(v).attrs).some(k => /^on/i.test(k)) && !Object.keys(gumbVloga(v).attrs).some(k => /^on/i.test(k))), "izvajalno: select in gumb brez on* atributov (le lastnosti-funkcije)");

    // izbira vloge sama ne kliče API-ja ne okna
    apiKlici.length = 0;
    const v1 = vrstice[0];
    izbira(v1).value = "admin"; izbira(v1).onchange();
    assert(apiKlici.length === 0 && potrdiKlici.length === 0, "izbira v seznamu NE pokliče API-ja in ne odpre okna");
    assert(gumbVloga(v1).disabled === false, "izbira druge vloge odklene gumb");

    // preklic: nazaj na prejšnjo vrednost, brez PATCH
    potrdiOdgovor = null;
    await gumbVloga(v1).onclick();
    assert(potrdiKlici.length === 1 && apiKlici.length === 0, "preklic: okno odprto, API ni poklican", { potrdi: potrdiKlici.length, api: apiKlici });
    assert(izbira(v1).value === "user", "preklic vrne izbiro na prejšnjo vrednost", izbira(v1).value);
    const o1 = potrdiKlici[0];
    assert(o1.vpis === ZLO[0] && o1.razlog === "obvezen" && o1.nevarno === true, "user → admin: vpis = e-naslov uporabnika, razlog obvezen, nevarno", { vpis: o1.vpis, razlog: o1.razlog });
    const okoli = new El("div"); okoli.append(...[].concat(o1.vsebina).filter(Boolean));
    const pV = pregled(okoli);
    assert(pV.elementi.every(t => new Set(["div", "b", "s"]).has(t)), "vsebina okna: samo div/b/s (podatki kot besedilo)", [...new Set(pV.elementi)]);
    assert(pV.besedila.join("").includes("user") && pV.besedila.join("").includes("admin") && pV.besedila.join("").includes(ZLO[0]), "vsebina okna kaže »prej → potem«", pV.besedila);

    // potrditev: PATCH z vlogo in razlogom
    izbira(v1).value = "admin"; potrdiOdgovor = { razlog: "nov vodja" }; apiKlici.length = 0;
    await gumbVloga(v1).onclick();
    const patch = apiKlici.find(k => k[0] === "PATCH");
    assert(patch && patch[1] === "/admin/api/users/1" && JSON.stringify(patch[2]) === JSON.stringify({ role: "admin", reason: "nov vodja" }), "potrditev: PATCH { role, reason }", apiKlici);

    // stroge in nestroge spremembe
    const preveri = async (prej, potem, stroga) => {
      potrdiKlici.length = 0; potrdiOdgovor = null;
      odgovoriU = [uporabnik(9, prej, { email: "u9@outly.si" })]; await naloziUporabnike();
      const r = []; sprehod($("uTabela"), (e) => { if (e.nodeType === 1 && e.tagName === "tr" && e.children.some(c => c.tagName === "td")) r.push(e); });
      izbira(r[0]).value = potem; izbira(r[0]).onchange(); await gumbVloga(r[0]).onclick();
      const o = potrdiKlici[0];
      assert(o && (o.vpis === "u9@outly.si") === stroga && o.razlog === (stroga ? "obvezen" : "neobvezen"), `${prej} → ${potem}: ${stroga ? "vpis e-naslova + obvezen razlog" : "brez vpisa, neobvezen razlog"}`, o && { vpis: o.vpis, razlog: o.razlog });
    };
    for (const [a, b2, st] of [["user", "business", false], ["business", "user", false], ["user", "admin", true], ["user", "backup", true], ["business", "admin", true], ["admin", "user", true], ["admin", "business", true], ["admin", "backup", true], ["backup", "user", false], ["backup", "business", false]]) await preveri(a, b2, st);
  }

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
