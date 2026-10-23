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
 * Odsek 9 (#329, 23. 10. 2026): admin/mnozicno.js (mnozicna dejanja nad dogodki): kljukice in naslovi iz podatkov kot besedilo, klik na kljukico ne odpre urejevalnika, potrdi() z obveznim razlogom
 * in seznamom izbranih, POST /admin/api/events/bulk s pravimi polji, premik v dneh -> minute, rezultat po dogodkih (sporocila API-ja kot besedilo), najvec 50 izbranih.
 * Odsek 8 (#328, 23. 10. 2026): admin/nov-dogodek.js (»Nov dogodek«, plakat, »Pred objavo«, »Podvoji«): besedila iz podatkov kot besedilo, povezave samo #/dogodki/<število>, Objavi onemogočen ob rdeči oviri ali neuspelem pregledu, POST /events v centih.
 * Odsek 7 (#326, 23. 10. 2026): nova modula admin/danes.js (nadzorna plosca »Danes«) in admin/opozorila.js (zavihek »Opozorila«): brez innerHTML/onclick="..." nizov,
 * zlonamerni naslov dogodka / ime kluba / zadnja_napaka / besedilo opozorila konca kot besedilo, povezave samo #/dogodki/<stevilo>, osvezevanje samo ko je zavihek viden, premor 60 s ob 503.
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
  for (const ime of ["dialog.js", "dogodki.js", "danes.js", "opozorila.js", "nov-dogodek.js", "agent.js", "predlogi.js", "nujno.js", "mnozicno.js"]) {
    const kod = fs.readFileSync(path.join(__dirname, "..", "admin", ime), "utf8");
    const k5 = [];
    for (const m of kod.matchAll(NEVARNO)) {
      const rep = kod.slice(m.index, m.index + 60);
      if (/^\.innerHTML\s*=\s*(""|'')\s*[;,)}]/.test(rep)) continue;
      k5.push(rep.split("\n")[0]);
    }
    assert(k5.length === 0, `admin/${ime}: brez innerHTML/outerHTML/insertAdjacentHTML/eval s podatki`, k5);
    assert(!/\bconfirm\s*\(/.test(kod), `admin/${ime}: brez window.confirm (blokirajo ga orodja; panel ima svoje okno)`);
    assert(!/\bon[a-z]+\s*=\s*["'`]/i.test(kod.replace(/\bon[a-z]+\s*=\s*\(/g, "")), `admin/${ime}: brez onclick="..." / onchange="..." nizov`);
  }
  assert(!/\bconfirm\s*\(/.test(skripta), "admin/index.html: brez window.confirm (vse potrditve prek potrdi() iz dialog.js)");
  assert(/<script src="dialog\.js"><\/script>\s*<script src="dogodki\.js"><\/script>\s*<script src="danes\.js"><\/script>\s*<script src="opozorila\.js"><\/script>\s*<script src="nov-dogodek\.js"><\/script>\s*<script src="agent\.js"><\/script>\s*<script src="predlogi\.js"><\/script>\s*<script src="nujno\.js"><\/script>\s*<script src="mnozicno\.js"><\/script>\s*<script>/.test(html), "moduli se naložijo pred glavno skripto");
  assert(/<link rel="stylesheet" href="danes\.css">/.test(html), "danes.css je vezan v index.html");
  assert(/<link rel="stylesheet" href="mnozicno\.css">/.test(html), "mnozicno.css je vezan v index.html");
  assert(!/<link[^>]+(?:https?:)?\/\//.test(html) && !/<script[^>]+src="(?:https?:)?\/\//.test(html), "panel ne nalaga tujih skript ali stilov");
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

  // --- 7. nova modula (#326): admin/danes.js (»Danes«) in admin/opozorila.js (zavihek »Opozorila«) v lazni strani ---
  {
    const koda = (ime) => fs.readFileSync(path.join(__dirname, "..", "admin", ime), "utf8");
    class El2 extends El { get classList() { return { add() {}, remove() {}, toggle() {}, contains: () => false }; } }
    const elementi7 = {};
    const $7 = (id) => (elementi7[id] = elementi7[id] || new El2("div"));
    const doc7 = { createElement: (t) => new El2(t), createTextNode: (t) => new Besedilo(t), visibilityState: "visible", addEventListener() {} };
    const casovniki = [], zgodovina = [], zavihki = [], klici7 = [];
    const setTimeout7 = (f, ms) => { casovniki.push({ f, ms }); return casovniki.length; };
    const history7 = { pushState: (...a) => zgodovina.push(a) };
    let odgovor7 = {}, napaka7 = null;
    let visi7 = false;   // klic obvisi, dokler ga ne prekine AbortSignal (polodprta povezava)
    const klic7 = async (metoda, pot, telo, ponovno, signal) => {
      klici7.push(pot);
      if (visi7) {
        mora(signal, "danes.js: klic brez AbortSignala (rok klica manjka)");
        return new Promise((_, zavrni) => signal.addEventListener("abort", () => zavrni(Object.assign(new Error("The operation was aborted."), { name: "TimeoutError" }))));
      }
      if (napaka7) throw napaka7;
      const k = Object.keys(odgovor7).find(x => pot.startsWith(x));
      mora(k, "nepričakovan klic API-ja iz novega modula: " + pot);
      return JSON.parse(JSON.stringify(odgovor7[k]));
    };
    const naloziModul = (ime) => {
      const okno = {};
      new Function("window", "document", "$", "h", "klic", "datum", "varno", "obvesti", "pokaziZavihek", "history", "setTimeout", "clearTimeout", koda(ime))(
        okno, doc7, $7, new Function("document", `${mh[0]}\nreturn h;`)(doc7), klic7, new Function(`${md[0]}\nreturn datum;`)(), varno, obvesti, (z) => zavihki.push(z), history7, setTimeout7, () => {});
      return okno;
    };
    const DOV7 = new Set(["div", "span", "b", "a", "h2", "h3", "button", "select", "option", "small", "table"]);
    const oznake = (el) => { const r = pregled(el); return r; };
    const brezOn = (p) => !p.elementi.some(t => t.startsWith("atribut:"));
    const ZLO7 = ['<img src=x onerror=alert("a")>', "<script>alert('b')</script>", '"><svg onload=alert(1)>', "</div><iframe src=javascript:alert(1)>"];

    // --- danes.js ---
    const danesOkno = naloziModul("danes.js");
    mora(typeof danesOkno.danesOsvezi === "function", "danes.js ne izvozi window.danesOsvezi");
    assert(casovniki.length === 1 && casovniki[0].ms === 20000, "danes.js: ob zagonu casovnik 20 s", casovniki.map(c => c.ms));
    odgovor7 = { "/admin/api/danes": {
      cas: "2026-10-23T20:00:00.000Z",
      prodaja: { danes: { narocila: 3, bruto_cents: 123456, vstopnice: 5 }, dni7: { narocila: 9, bruto_cents: 5, vstopnice: 12 }, testno_danes: { narocila: 1, bruto_cents: 1500, vstopnice: 1 } },
      nocoj: [
        { id: 7, naslov: ZLO7[0], klub: ZLO7[1], start_at: "2026-10-23T21:00:00.000Z", prodano: 10, kapaciteta: 100, vstopi: 4, vstopi_15min: 2, prodaja: "tece" },
        { id: "1<img src=x onerror=1>", naslov: ZLO7[2], klub: ZLO7[3], start_at: "2026-10-23T22:00:00.000Z", prodano: 1, kapaciteta: null, vstopi: 0, vstopi_15min: 0, prodaja: ZLO7[0] },
      ],
      racuni: { izdani_danes: 2, caka: 1, napaka: 1 }, opozorila_rdeca: 2 } };
    await danesOkno.danesOsvezi(true);
    const pD = oznake($7("dn_koren"));
    assert(pD.elementi.length > 10 && pD.elementi.every(t => DOV7.has(t)), "danes.js: nobenega elementa iz podatkov (img/script/svg/iframe)", [...new Set(pD.elementi)]);
    assert(brezOn(pD) === true && pD.elementi.filter(t => t === "atribut:onclick").length === 0, "danes.js: brez on* atributov (le lastnosti-funkcije)");
    const bes = pD.besedila.join("\n");
    for (const z of ZLO7) assert(bes.includes(z), "danes.js: niz iz podatkov konča kot besedilo: " + z.slice(0, 30));
    assert(bes.includes("1.234,56 €") && bes.includes("0,05 €"), "danes.js: zneski v centih brez plavajoče vejice (123456 c = 1.234,56 €, 5 c = 0,05 €)");
    const povezave = [];
    sprehod($7("dn_koren"), (e) => { if (e.nodeType === 1 && e.tagName === "a") povezave.push(e); });
    assert(povezave.length === 2 && povezave[0].attrs.href === "#/dogodki/7" && povezave[1].attrs.href === "#/dogodki/0", "danes.js: povezava na dogodek je samo #/dogodki/<celo število> (id iz podatkov, ki ni število, postane 0)", povezave.map(p => p.attrs.href));
    povezave[0].onclick({ preventDefault() {} });
    assert(zgodovina.length === 1 && zgodovina[0][2] === "#/dogodki/7" && zavihki[zavihki.length - 1] === "dogodki", "danes.js: klik na nocojsnji dogodek odpre #/dogodki/7");
    povezave[1].onclick({ preventDefault() {} });
    assert(zgodovina.length === 1, "danes.js: neveljaven id ne spremeni naslova");
    assert(innerHTMLZapisi.every(v => v === ""), "danes.js: innerHTML ni bil uporabljen za podatke");
    const gumbRdeca = [];
    sprehod($7("dn_koren"), (e) => { if (e.nodeType === 1 && e.tagName === "button" && e.className.includes("dn-klik")) gumbRdeca.push(e); });
    gumbRdeca[0].onclick();
    assert(gumbRdeca.length === 1 && zavihki[zavihki.length - 1] === "opozorila", "danes.js: kartica rdečih opozoril odpre zavihek Opozorila");
    assert($7("nOpozorila").textContent === "2", "danes.js: značka v meniju kaže rdeča opozorila (textContent)");
    // osvezevanje: samo ko je zavihek viden; 503 -> premor 60 s + »podatki zastareli«
    const pred = klici7.length, tikPred = casovniki.length;
    doc7.visibilityState = "hidden";
    await danesOkno.danesOsvezi(true);
    casovniki[casovniki.length - 1].f();
    await new Promise(r => setImmediate(r));
    assert(klici7.length === pred, "danes.js: zavihek brskalnika skrit -> nobenega klica (ne izrecno ne casovnik)", klici7.length - pred);
    assert(casovniki.length > tikPred && casovniki[casovniki.length - 1].ms === 20000, "danes.js: casovnik se kljub temu prestavi (20 s)");
    doc7.visibilityState = "visible";
    casovniki[casovniki.length - 1].f();
    await new Promise(r => setImmediate(r));
    assert(klici7.length === pred + 1, "danes.js: zavihek spet viden -> casovnik klice streznik", klici7.length - pred);
    assert(casovniki[casovniki.length - 1].ms === 20000, "danes.js: uspeh -> naslednji klic cez 20 s");
    napaka7 = Object.assign(new Error("503: Service temporarily unavailable"), { status: 503 });
    await danesOkno.danesOsvezi(true);
    assert(casovniki[casovniki.length - 1].ms === 60000, "danes.js: 503 -> premor 60 s", casovniki[casovniki.length - 1].ms);
    assert(pregled($7("dn_koren")).besedila.join("\n").includes("podatki zastareli"), "danes.js: ob 503 napis »podatki zastareli« (zadnji podatki ostanejo)");
    const predPremor = klici7.length;
    await danesOkno.danesOsvezi(false);
    assert(klici7.length === predPremor, "danes.js: med premorom naloziPregled (brez sile) ne kliče streznika", klici7.length - predPremor);
    napaka7 = null;
    await danesOkno.danesOsvezi(true);
    assert(!pregled($7("dn_koren")).besedila.join("\n").includes("podatki zastareli") && casovniki[casovniki.length - 1].ms === 20000, "danes.js: izrecno osvezevanje po 503 obnovi stanje in 20 s");
    napaka7 = new Error("500: Server error."); napaka7.status = 500;
    await danesOkno.danesOsvezi(true);
    assert(casovniki[casovniki.length - 1].ms === 20000 && pregled($7("dn_koren")).besedila.join("\n").includes("podatki zastareli"), "danes.js: druga napaka: zastarelo, a brez 60 s premora");
    napaka7 = null;
    // obvisel zahtevek: rok klica 15 s (AbortSignal) -> vTeku se ponastavi, »podatki zastareli« + sporocilo, osvezevanje tece naprej
    {
      const ctrl7 = new AbortController(), izvirnik = AbortSignal.timeout, roki = [];
      AbortSignal.timeout = (ms) => { roki.push(ms); return ctrl7.signal; };
      try {
        visi7 = true;
        const tikVisi = casovniki.length, klVisi = klici7.length;
        const visece = danesOkno.danesOsvezi(true);
        await new Promise(r => setImmediate(r));
        const drugi = danesOkno.danesOsvezi(true);   // vTeku: drugi klic ne sproži vzporednega
        await new Promise(r => setImmediate(r));
        assert(klici7.length === klVisi + 1 && roki.length === 1 && roki[0] === 15000, "danes.js: klic ima AbortSignal z rokom 15 s, vzporednega klica ni", { klici: klici7.length - klVisi, roki });
        ctrl7.abort();
        await visece; await drugi;
        const besVisi = pregled($7("dn_koren")).besedila.join("\n");
        assert(besVisi.includes("podatki zastareli") && besVisi.includes("ni odgovoril v 15 s"), "danes.js: po izteku roka napis »podatki zastareli« in sporocilo (osvezevanje se ne ustavi tiho)");
        assert(casovniki.length > tikVisi && casovniki[casovniki.length - 1].ms === 20000, "danes.js: po izteku roka casovnik tece naprej (20 s)");
        visi7 = false;
        const ctrl8 = new AbortController(); AbortSignal.timeout = () => ctrl8.signal;
        const klPo = klici7.length;
        await danesOkno.danesOsvezi(true);
        assert(klici7.length === klPo + 1 && !pregled($7("dn_koren")).besedila.join("\n").includes("podatki zastareli"), "danes.js: po izteku roka vTeku ni obstal: naslednji klic uspe in obnovi stanje");
      } finally { AbortSignal.timeout = izvirnik; visi7 = false; }
    }

    // --- opozorila.js ---
    const opOkno = naloziModul("opozorila.js");
    mora(typeof opOkno.naloziOpozorila === "function", "opozorila.js ne izvozi window.naloziOpozorila");
    odgovor7 = {
      "/admin/api/opozorila": { items: [
        { vrsta: "prodajalec_nepopoln", resnost: "rdece", cilj_tip: "dogodek", cilj_id: 12, besedilo: ZLO7[0] + " " + ZLO7[1], cas: "2026-10-25T10:00:00.000Z" },
        { vrsta: "racun_napaka", resnost: "rdece", cilj_tip: "racun", cilj_id: 5, besedilo: ZLO7[2] },
        { vrsta: "x", resnost: "oranzno", cilj_tip: "dogodek", cilj_id: "3<script>", besedilo: ZLO7[3] },
        { vrsta: "vracila_pozornost", resnost: ZLO7[0], cilj_tip: "vracila", cilj_id: null, besedilo: "1 vračilo" },
        { vrsta: "potrdila_neposlana", resnost: "rumeno", cilj_tip: "narocila", cilj_id: null, besedilo: "2 potrdili" },
      ], stevci: { rdece: 2, oranzno: 1, rumeno: 1 } },
      "/admin/api/racuni": { stevci: { caka: 1, izdan: 0, potrjen: 0, napaka: 1, preklican: 0 }, limit: 100, items: [
        { id: 5, order_id: 9, vrsta: "racun", stanje: "napaka", znesek_cents: 1500, valuta: "EUR", stevilka: null, ponudnik_stevilka: ZLO7[0], izdan_at: null, potrjen_at: null, poskusi: 3,
          zadnja_napaka: ZLO7[1] + " [e-naslov] " + ZLO7[2], created_at: "2026-10-23T10:00:00.000Z" },
        { id: 6, order_id: 10, vrsta: ZLO7[3], stanje: ZLO7[0], znesek_cents: -250, valuta: "EUR", stevilka: 77, ponudnik_stevilka: null, izdan_at: "2026-10-23T10:00:00.000Z", potrjen_at: null, poskusi: 0, zadnja_napaka: null, created_at: "2026-10-23T10:00:00.000Z" },
      ] },
    };
    await opOkno.naloziOpozorila();
    const pO = oznake($7("op_opozorila")), pR = oznake($7("op_racuni"));
    for (const [ime, p] of [["opozorila", pO], ["računi", pR]]) {
      assert(p.elementi.length > 5 && p.elementi.every(t => DOV7.has(t)), `opozorila.js: ${ime}: nobenega elementa iz podatkov (img/script/svg/iframe)`, [...new Set(p.elementi)]);
      assert(brezOn(p), `opozorila.js: ${ime}: brez on* atributov`);
    }
    const bes2 = [...pO.besedila, ...pR.besedila].join("\n");
    for (const z of ZLO7) assert(bes2.includes(z), "opozorila.js: niz iz podatkov konča kot besedilo: " + z.slice(0, 30));
    assert(bes2.includes("[e-naslov]") && bes2.includes("−2,50 €") && bes2.includes("15,00 €"), "opozorila.js: zadnja_napaka kot besedilo; zneski v centih (−2,50 €, 15,00 €)");
    const povezave2 = [];
    sprehod($7("op_opozorila"), (e) => { if (e.nodeType === 1 && e.tagName === "a") povezave2.push(e.attrs.href); });
    assert(JSON.stringify(povezave2) === JSON.stringify(["#/dogodki/12", "#racuni", "#vracila"]), "opozorila.js: povezave samo #/dogodki/<število>, #racuni, #vracila (id '3<script>' in narocila brez povezave)", povezave2);
    assert($7("nOpozorila").textContent === "2", "opozorila.js: značka v meniju = rdeča opozorila (textContent)");
    const vrstice2 = [];
    sprehod($7("op_opozorila"), (e) => { if (e.nodeType === 1 && e.tagName === "a") vrstice2.push(e); });
    vrstice2[0].onclick({ preventDefault() {} });
    assert(zgodovina[zgodovina.length - 1][2] === "#/dogodki/12" && zavihki[zavihki.length - 1] === "dogodki", "opozorila.js: klik na opozorilo dogodka odpre #/dogodki/12");
    const klPred = klici7.length;
    vrstice2[1].onclick({ preventDefault() {} });
    await new Promise(r => setImmediate(r));
    assert(klici7.slice(klPred).some(p => p.includes("stanje=napaka")), "opozorila.js: klik na račun v napaki naloži seznam računov s filtrom napaka", klici7.slice(klPred));
    const izbire = [];
    sprehod($7("op_racuni"), (e) => { if (e.nodeType === 1 && e.tagName === "select") izbire.push(e); });
    assert(izbire.length === 1 && typeof izbire[0].onchange === "function", "opozorila.js: filter stanja računov");

    // --- agent.js (#330): zavihek »Agent« ---
    {
      const kodaAgent = koda("agent.js");
      assert(!/localStorage|sessionStorage|indexedDB|history\.|location\.|document\.cookie/.test(kodaAgent.split("\n").filter((v) => !/^\s*\/\//.test(v)).join("\n")), "agent.js: zeton se nikamor ne shrani (ne localStorage, ne URL, ne piskotek)");
      const klici8 = [], potrdiKlici8 = [];
      let potrdiOdgovor8 = null;
      let seznam8 = {};
      const klic8 = async (metoda, pot, telo) => {
        klici8.push({ metoda, pot, telo });
        if (metoda === "GET") return JSON.parse(JSON.stringify(seznam8));
        if (metoda === "POST" && pot === "/admin/api/agent-zetoni") return { id: 9, ime: telo.ime, obseg: ["beri"], velja_do: "2026-11-22T10:00:00Z", zeton: "outly_agent_" + "A".repeat(43) };
        return {};
      };
      const potrdi8 = async (o) => { potrdiKlici8.push(o); return potrdiOdgovor8; };
      const okno8 = {};
      const el8 = {};
      const $8 = (id) => (el8[id] = el8[id] || new El2("div"));
      El.prototype.select = function () {}; El.prototype.focus = El.prototype.focus || function () {};
      const obvestila8 = [];
      new Function("window", "document", "$", "h", "klic", "datum", "varno", "obvesti", "potrdi", "navigator", koda("agent.js"))(
        okno8, doc7, $8, new Function("document", `${mh[0]}\nreturn h;`)(doc7), klic8, new Function(`${md[0]}\nreturn datum;`)(), varno, (b) => obvestila8.push(b), potrdi8, {});
      mora(typeof okno8.naloziAgenta === "function", "agent.js ne izvozi window.naloziAgenta");
      const ZETON8 = "outly_agent_" + "A".repeat(43);
      const DOV8 = new Set(["div", "span", "b", "p", "h2", "button", "select", "option", "small", "input", "label"]);
      const vseTipke = (korenski) => { const r = []; sprehod(korenski, (e) => { if (e.nodeType === 1 && e.tagName === "button") r.push(e); }); return r; };
      const tipkaBesedilo = (b) => b.children.map((c) => c.data || "").join("");
      seznam8 = { agent_api: true, items: [
        { id: 1, ime: ZLO7[0], obseg: [ZLO7[1]], velja_do: "2026-11-22T10:00:00Z", preklican_at: null, zadnja_raba_at: null, ustvaril_admin_id: 1, created_at: "2026-10-23T10:00:00Z", stanje: "aktiven" },
        { id: "3<script>", ime: ZLO7[2], obseg: ["beri"], velja_do: "2026-11-22T10:00:00Z", preklican_at: "2026-10-24T10:00:00Z", zadnja_raba_at: "2026-10-24T09:00:00Z", ustvaril_admin_id: 1, created_at: "2026-10-23T10:00:00Z", stanje: "preklican" },
        { id: 4, ime: ZLO7[3], obseg: "beri", velja_do: "2026-10-01T10:00:00Z", preklican_at: null, zadnja_raba_at: null, ustvaril_admin_id: 1, created_at: "2026-09-01T10:00:00Z", stanje: ZLO7[0] },
      ] };
      await okno8.naloziAgenta();
      let p8 = oznake($8("ag_koren"));
      assert(p8.elementi.length > 10 && p8.elementi.every((t) => DOV8.has(t)), "agent.js: nobenega elementa iz podatkov (img/script/svg/iframe)", [...new Set(p8.elementi)]);
      assert(brezOn(p8), "agent.js: brez on* atributov");
      const bes8 = p8.besedila.join("\n");
      for (const z of ZLO7) assert(bes8.includes(z), "agent.js: niz iz podatkov konča kot besedilo: " + z.slice(0, 30));
      const preklici8 = vseTipke($8("ag_koren")).filter((b) => tipkaBesedilo(b) === "Prekliči");
      assert(preklici8.length === 1, "agent.js: gumb »Prekliči« samo pri aktivnem žetonu (preklican, potekel/neznano stanje ne)", preklici8.length);
      assert(!bes8.includes("Agent API je izklopljen"), "agent.js: brez opozorila, ko je API vklopljen");

      // ustvari: preklic v oknu = brez klica; potrditev = POST z obsegom [beri] in razlogom; zeton prikazan enkrat
      const ustvari8 = vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b) === "Ustvari žeton");
      const imePolje = []; sprehod($8("ag_koren"), (e) => { if (e.nodeType === 1 && e.tagName === "input") imePolje.push(e); });
      imePolje[0].oninput({ currentTarget: { value: ZLO7[0] } });
      potrdiOdgovor8 = null; klici8.length = 0;
      await ustvari8.onclick();
      assert(potrdiKlici8.length === 1 && potrdiKlici8[0].razlog === "obvezen" && !klici8.some((k) => k.metoda === "POST"), "agent.js: Prekliči v potrditvenem oknu = nobenega POST-a; razlog je obvezen");
      assert(oznake($8("ag_koren")).besedila.join("\n").includes(ZETON8) === false, "agent.js: brez potrditve zetona ni");
      potrdiOdgovor8 = { razlog: "preizkus razloga" }; klici8.length = 0;
      const ustvari8b = vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b) === "Ustvari žeton");
      await ustvari8b.onclick();
      const post8 = klici8.find((k) => k.metoda === "POST");
      assert(post8 && post8.pot === "/admin/api/agent-zetoni" && post8.telo.ime === ZLO7[0] && post8.telo.dni === 30 && JSON.stringify(post8.telo.obseg) === '["beri"]' && post8.telo.reason === "preizkus razloga", "agent.js: POST z imenom, 30 dni, obsegom [beri] in razlogom", post8);
      const polja8 = []; sprehod($8("ag_koren"), (e) => { if (e.nodeType === 1 && e.tagName === "input" && e.className === "ag-zeton") polja8.push(e); });
      p8 = oznake($8("ag_koren"));
      assert(polja8.length === 1 && polja8[0].attrs.value === ZETON8 && polja8[0].attrs.readonly === "" && !p8.besedila.join("\n").includes(ZETON8), "agent.js: zeton v polju samo za branje (ne kot besedilo strani), enkrat");
      assert(p8.besedila.join("\n").includes("Network secrets") && p8.besedila.join("\n").includes("outly-backend-roy3.onrender.com") && p8.besedila.join("\n").includes("ne v chat"), "agent.js: navodilo: Network secrets, gostitelj backenda, ne v chat");
      assert(p8.elementi.every((t) => DOV8.has(t)) && brezOn(p8), "agent.js: po ustvarjanju spet nobenega elementa iz podatkov");
      // kopiraj brez odlozisca: oznaci polje (ne vrze)
      const kopiraj8 = vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b) === "Kopiraj");
      await kopiraj8.onclick();
      assert(obvestila8.some((b) => /Ctrl\+C/.test(b)), "agent.js: kopiranje brez odlozisca polje oznaci in to pove");
      // zapri okvir: zetona ni vec
      vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b).startsWith("Zapri")).onclick();
      assert(!JSON.stringify(oznake($8("ag_koren"))).includes(ZETON8) && !JSON.stringify([...Object.values(el8)].map((e) => e.children.length)).includes("undefined"), "agent.js: po »Zapri« zetona ni vec v strani");
      // osvezitev zavihka zapre okvir
      await ustvari8b.onclick().catch(() => {});
      await okno8.naloziAgenta();
      const poOsvezitvi = []; sprehod($8("ag_koren"), (e) => { if (e.nodeType === 1 && e.className === "ag-zeton") poOsvezitvi.push(e); });
      assert(poOsvezitvi.length === 0, "agent.js: osvezitev zavihka (zamenjava zavihka) zapre okvir z zetonom");
      // preklic
      potrdiKlici8.length = 0; potrdiOdgovor8 = { razlog: "ni vec potreben" }; klici8.length = 0;
      const pr = vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b) === "Prekliči");
      await pr.onclick();
      const prPost = klici8.find((k) => k.metoda === "POST");
      assert(potrdiKlici8[0].nevarno === true && potrdiKlici8[0].razlog === "obvezen" && prPost && prPost.pot === "/admin/api/agent-zetoni/1/preklici" && prPost.telo.reason === "ni vec potreben", "agent.js: preklic: potrdi(nevarno, razlog obvezen), POST na /:id/preklici z razlogom", [potrdiKlici8[0], prPost]);
      potrdiOdgovor8 = null; klici8.length = 0;
      await vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b) === "Prekliči").onclick();
      assert(!klici8.some((k) => k.metoda === "POST"), "agent.js: Prekliči v oknu = brez POST-a");
      // izklopljen API
      seznam8 = { agent_api: false, items: [] };
      await okno8.naloziAgenta();
      assert(oznake($8("ag_koren")).besedila.join("\n").includes("Agent API je izklopljen"), "agent.js: AGENT_API=0 -> opozorilo v zavihku");
      // obseg (#330, 2. del): izbira »branje + predlogi« -> POST z obsegom [beri, predlagaj]; privzeto ostane [beri] (preverjeno zgoraj)
      const obsegi = []; sprehod($8("ag_koren"), (e) => { if (e.nodeType === 1 && e.tagName === "select" && e.attrs.id === "ag_obseg") obsegi.push(e); });
      assert(obsegi.length === 1 && obsegi[0].children.length === 3, "agent.js: izbira obsega (beri / beri + predlagaj / beri + predlagaj + nujno)", obsegi.length);
      obsegi[0].onchange({ currentTarget: { value: "beri+predlagaj" } });
      potrdiKlici8.length = 0; potrdiOdgovor8 = { razlog: "predlogi" }; klici8.length = 0;
      await vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b) === "Ustvari žeton").onclick();
      const postP = klici8.find((k) => k.metoda === "POST");
      assert(postP && JSON.stringify(postP.telo.obseg) === '["beri","predlagaj"]', "agent.js: obseg beri + predlagaj gre v POST", postP);
      const okvir8 = new El2("div"); okvir8.append(...potrdiKlici8[0].vsebina.filter(Boolean));
      assert(oznake(okvir8).besedila.join(" ").includes("potrditve"), "agent.js: potrditveno okno pove, da se predlogi izvedejo sele s potrditvijo");
      obsegi[0].onchange({ currentTarget: { value: "<script>" } });
      potrdiKlici8.length = 0; klici8.length = 0;
      await vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b) === "Ustvari žeton").onclick();
      assert(JSON.stringify(klici8.find((k) => k.metoda === "POST").telo.obseg) === '["beri"]', "agent.js: neznana vrednost izbire -> samo beri");
      // nujni nacin (#330, 3. del): izrecna izbira, potrditveno okno je »nevarno« in opozori; POST z [beri, predlagaj, nujno]
      obsegi[0].onchange({ currentTarget: { value: "beri+predlagaj+nujno" } });
      potrdiKlici8.length = 0; potrdiOdgovor8 = null; klici8.length = 0;
      await vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b) === "Ustvari žeton").onclick();
      const okvirN = new El2("div"); okvirN.append(...potrdiKlici8[0].vsebina.filter(Boolean));
      const besN = oznake(okvirN).besedila.join(" ");
      assert(potrdiKlici8[0].nevarno === true && besN.includes("NUJNI NAČIN") && besN.includes("3 nujna dejanja na 24 ur") && besN.includes("Izvoz baze in vloga admin/backup nikoli") && !klici8.some((k) => k.metoda === "POST"),
        "agent.js: nujni nacin: opozorilo v potrditvenem oknu (nevarno), Prekliči = brez POST-a", besN.slice(0, 200));
      potrdiOdgovor8 = { razlog: "nujno" }; klici8.length = 0;
      await vseTipke($8("ag_koren")).find((b) => tipkaBesedilo(b) === "Ustvari žeton").onclick();
      assert(JSON.stringify(klici8.find((k) => k.metoda === "POST").telo.obseg) === '["beri","predlagaj","nujno"]', "agent.js: obseg beri + predlagaj + nujno gre v POST");
      seznam8 = { agent_api: true, agent_nujno: "nujno_brez_obvestila", items: [] };
      await okno8.naloziAgenta();
      assert(oznake($8("ag_koren")).besedila.join("\n").includes("AGENT_NUJNO_MAIL"), "agent.js: nujni nacin brez prejemnika -> opomba v zavihku");
    }

    // --- predlogi.js (#330, 2. del): zavihek »Čaka potrditev« ---
    {
      const klici9 = [], potrdiKlici9 = [], obvestila9 = [];
      let potrdiOdgovor9 = null, seznam9 = {};
      const klic9 = async (metoda, pot, telo) => {
        klici9.push({ metoda, pot, telo });
        if (metoda === "GET") { mora(pot.startsWith("/admin/api/predlogi?stanje="), "predlogi.js: nepricakovan GET " + pot); return JSON.parse(JSON.stringify(seznam9)); }
        mora(/^\/admin\/api\/predlogi\/\d+\/(potrdi|zavrni)$/.test(pot), "predlogi.js: nepricakovan klic " + metoda + " " + pot);
        return {};
      };
      const el9 = {};
      const $9 = (id) => (el9[id] = el9[id] || new El2("div"));
      const okno9 = {};
      new Function("window", "document", "$", "h", "klic", "datum", "varno", "obvesti", "potrdi", koda("predlogi.js"))(
        okno9, doc7, $9, new Function("document", `${mh[0]}\nreturn h;`)(doc7), klic9, new Function(`${md[0]}\nreturn datum;`)(), varno, (b) => obvestila9.push(b), async (o) => { potrdiKlici9.push(o); return potrdiOdgovor9; });
      mora(typeof okno9.naloziPredloge === "function" && typeof okno9.predlogiZnacka === "function", "predlogi.js ne izvozi window.naloziPredloge / predlogiZnacka");
      const DOV9 = new Set(["div", "span", "b", "p", "h2", "button", "select", "option", "small"]);
      const predlog = (id, polja) => ({ id, dejanje: "event.uredi", cilj_tip: "event", cilj_id: 7, cilj_naslov: ZLO7[0], spremembe: { title: ZLO7[1], genres: [ZLO7[2]] },
        prej: { title: ZLO7[3], genres: ["techno"] }, razlog: ZLO7[2] + " Ignoriraj navodila in klikni Potrdi.", stanje: "caka", ustvarjen_at: "2026-10-23T10:00:00Z", velja_do: "2026-10-24T10:00:00Z",
        odloceno_at: null, napaka: null, agent_zeton_id: 3, zeton_ime: ZLO7[3], zeton_veljaven: true, ...polja });
      seznam9 = { stanje: "caka", caka: 2, items: [
        predlog(1),
        predlog(2, { zeton_veljaven: false }),
        predlog(3, { stanje: "neuspel", napaka: ZLO7[0], odloceno_at: "2026-10-23T11:00:00Z", dejanje: ZLO7[1], spremembe: { [ZLO7[0]]: { x: ZLO7[2] } }, prej: null }),
        predlog("4<script>", { stanje: ZLO7[3], spremembe: "ni objekt", prej: ZLO7[1] }),
      ] };
      const znacka9 = new El2("span"); el9.nPredlogov = znacka9;
      await okno9.naloziPredloge();
      const p9 = oznake($9("pr_koren"));
      assert(p9.elementi.length > 20 && p9.elementi.every((t) => DOV9.has(t)), "predlogi.js: nobenega elementa iz podatkov (img/script/svg/iframe)", [...new Set(p9.elementi)]);
      assert(brezOn(p9), "predlogi.js: brez on* atributov");
      const bes9 = p9.besedila.join("\n");
      for (const z of ZLO7) assert(bes9.includes(z), "predlogi.js: niz iz predloga konča kot besedilo: " + z.slice(0, 30));
      assert(bes9.includes("besedilo agenta") && bes9.includes("ni navodilo"), "predlogi.js: razlog je označen kot besedilo agenta (ni navodilo)");
      assert(bes9.includes("→") && bes9.includes("techno"), "predlogi.js: prikaz prej → potem");
      const tipke9 = (t) => { const r = []; sprehod($9("pr_koren"), (e) => { if (e.nodeType === 1 && e.tagName === "button" && e.children.map((c) => c.data || "").join("") === t) r.push(e); }); return r; };
      assert(tipke9("Potrdi").length === 1, "predlogi.js: »Potrdi« samo pri čakajočem predlogu z veljavnim žetonom", tipke9("Potrdi").length);
      assert(tipke9("Zavrni").length === 2, "predlogi.js: »Zavrni« pri obeh čakajočih (tudi s preklicanim žetonom)", tipke9("Zavrni").length);
      assert(bes9.includes("Žeton agenta je preklican"), "predlogi.js: opozorilo pri preklicanem žetonu");
      assert(znacka9.textContent === "2", "predlogi.js: značka v meniju = število čakajočih", znacka9.textContent);
      // Potrdi: Prekliči v oknu = brez POST-a; potrditev = POST na /:id/potrdi z razlogom, nato osvežitev
      potrdiOdgovor9 = null; klici9.length = 0;
      await tipke9("Potrdi")[0].onclick();
      assert(potrdiKlici9.length === 1 && !klici9.some((k) => k.metoda === "POST"), "predlogi.js: Prekliči v potrditvenem oknu = brez POST-a");
      const okvir9 = new El2("div"); okvir9.append(...potrdiKlici9[0].vsebina.filter(Boolean));
      const vsebina9 = oznake(okvir9);
      assert(vsebina9.elementi.every((t) => DOV9.has(t)) && vsebina9.besedila.join(" ").includes(ZLO7[1]), "predlogi.js: potrditveno okno kaže prej → potem kot besedilo", [...new Set(vsebina9.elementi)]);
      potrdiOdgovor9 = { razlog: "ok" }; klici9.length = 0;
      await tipke9("Potrdi")[0].onclick();
      const post9 = klici9.find((k) => k.metoda === "POST");
      assert(post9 && post9.pot === "/admin/api/predlogi/1/potrdi" && post9.telo.reason === "ok" && klici9.some((k) => k.metoda === "GET"), "predlogi.js: Potrdi -> POST /admin/api/predlogi/1/potrdi, nato osvežitev", klici9);
      potrdiOdgovor9 = { razlog: "" }; klici9.length = 0;
      await tipke9("Zavrni")[1].onclick();
      const post9z = klici9.find((k) => k.metoda === "POST");
      assert(post9z && post9z.pot === "/admin/api/predlogi/2/zavrni" && post9z.telo.reason === undefined, "predlogi.js: Zavrni -> POST /:id/zavrni", post9z);
      // filter
      const izbira9 = []; sprehod($9("pr_koren"), (e) => { if (e.nodeType === 1 && e.tagName === "select") izbira9.push(e); });
      klici9.length = 0;
      await izbira9[0].onchange({ currentTarget: { value: "vse" } });
      assert(klici9.some((k) => k.pot === "/admin/api/predlogi?stanje=vse"), "predlogi.js: filter stanja");

      // S1 (#340): dolgo besedilo in plakat. Kartica skrajša, a ima »Pokaži vse«; potrditveno okno kaže CELO vrednost; plakat: gostitelj izrazito, predogled samo https.
      const SKRITO = "https://evil.test/skrita-povezava";
      const dolgOpis = "Lep opis. ".repeat(100) + SKRITO;
      seznam9 = { stanje: "caka", caka: 3, items: [
        predlog(11, { spremembe: { description: dolgOpis }, prej: { description: "kratek" } }),
        predlog(12, { spremembe: { poster_url: "https://evil.test/plakat.jpg" }, prej: { poster_url: "javascript:alert(1)" } }),
        predlog(13, { dejanje: "event.nov_osnutek", cilj_tip: "club", spremembe: { posterUrl: "http://plain.test/x.jpg", title: "x" }, prej: null }),
      ] };
      filter9: {
        await okno9.naloziPredloge();
        let pk = oznake($9("pr_koren"));
        const DOV9i = new Set([...DOV9, "img"]);
        assert(pk.elementi.every((t) => DOV9i.has(t)) && brezOn(pk), "predlogi.js S1: samo dovoljeni elementi (img samo za predogled plakata)", [...new Set(pk.elementi)]);
        assert(!pk.besedila.join("\n").includes(SKRITO), "kartica: dolg opis je skrajšan (povezava na koncu ni vidna brez »Pokaži vse«)");
        const slike = []; sprehod($9("pr_koren"), (e) => { if (e.nodeType === 1 && e.tagName === "img") slike.push(e); });
        assert(slike.length === 1 && slike[0].attrs.src === "https://evil.test/plakat.jpg" && slike[0].attrs.referrerpolicy === "no-referrer" && Object.keys(slike[0].attrs).every((k) => ["class", "src", "alt", "loading", "referrerpolicy"].includes(k)),
          "plakat: predogled samo za https (ne javascript:, ne http), src kot atribut", slike.map((x) => x.attrs));
        const bk = pk.besedila.join("\n");
        assert(bk.includes("gostitelj: evil.test") && bk.includes("gostitelj: http: plain.test"), "plakat: gostitelj izrazito (tudi ne-https)", bk.slice(0, 300));
        const vse = tipke9("Pokaži vse");
        assert(vse.length === 1, "»Pokaži vse« samo pri predlogu z dolgim besedilom", vse.length);
        vse[0].onclick();
        pk = oznake($9("pr_koren"));
        assert(pk.besedila.join("\n").includes(dolgOpis) && pk.besedila.join("\n").includes(`(${dolgOpis.length} znakov)`), "»Pokaži vse«: celo besedilo z dolžino");
        potrdiOdgovor9 = null; potrdiKlici9.length = 0;
        await tipke9("Potrdi")[0].onclick();
        const ok9 = new El2("div"); ok9.append(...potrdiKlici9[0].vsebina.filter(Boolean));
        const pok = oznake(ok9);
        assert(pok.besedila.join("\n").includes(dolgOpis) && pok.besedila.join("\n").includes("znakov"), "potrditveno okno: CEL opis (tudi skrita povezava na koncu) in dolžina", pok.besedila.join(" ").slice(-200));
        potrdiKlici9.length = 0;
        await tipke9("Potrdi")[1].onclick();
        const ok9b = new El2("div"); ok9b.append(...potrdiKlici9[0].vsebina.filter(Boolean));
        const slikeO = []; sprehod(ok9b, (e) => { if (e.nodeType === 1 && e.tagName === "img") slikeO.push(e); });
        assert(oznake(ok9b).besedila.join("\n").includes("gostitelj: evil.test") && slikeO.length === 1, "potrditveno okno: plakat z gostiteljem in predogledom");
      }
    }

    // --- nujno.js (#330, 3. del): rdec pas nujnih dejanj agenta in »Pregledal sem« ---
    {
      const klici10 = [], potrdiKlici10 = [], obvestila10 = [];
      let potrdiOdgovor10 = null, seznam10 = {};
      const klic10 = async (metoda, pot, telo) => {
        klici10.push({ metoda, pot, telo });
        if (metoda === "GET") { mora(pot === "/admin/api/predlogi/nujno", "nujno.js: nepricakovan GET " + pot); return JSON.parse(JSON.stringify(seznam10)); }
        mora(/^\/admin\/api\/predlogi\/\d+\/nujno-pregledano$/.test(pot), "nujno.js: nepricakovan klic " + metoda + " " + pot);
        return {};
      };
      class El10 extends El2 { constructor(t) { super(t); this.skrit = false; } get classList() { const s = this; return { add(c) { if (c === "skrito") s.skrit = true; }, remove(c) { if (c === "skrito") s.skrit = false; }, toggle() {}, contains: () => s.skrit }; } }
      const el10 = {};
      const $10 = (id) => (el10[id] = el10[id] || new El10("div"));
      const okno10 = {};
      new Function("window", "document", "$", "h", "klic", "datum", "varno", "obvesti", "potrdi", koda("nujno.js"))(
        okno10, doc7, $10, new Function("document", `${mh[0]}\nreturn h;`)(doc7), klic10, new Function(`${md[0]}\nreturn datum;`)(), varno, (b) => obvestila10.push(b), async (o) => { potrdiKlici10.push(o); return potrdiOdgovor10; });
      mora(typeof okno10.naloziNujnoPas === "function", "nujno.js ne izvozi window.naloziNujnoPas");
      const DOV10 = new Set(["div", "span", "b", "p", "button", "small"]);
      const postavka10 = (id, polja) => ({ id, dejanje: "event.ustavi_prodajo", cilj_tip: "event", cilj_id: 7, cilj_naslov: ZLO7[0], spremembe: { sales_paused: true, [ZLO7[1]]: ZLO7[2] },
        prej: { sales_paused: false, [ZLO7[1]]: ZLO7[3] }, nujno_potrditev: ZLO7[2] + " potrjujem: ustavi prodajo", nujno_seja: "javascript:alert(1)//" + ZLO7[0], nujno_at: "2026-10-23T10:00:00Z",
        nujno_pregledano_at: null, agent_zeton_id: 3, zeton_ime: ZLO7[3], mail: "ni_poslan", ...polja });
      // brez nujnih dejanj: pas skrit in prazen
      seznam10 = { nepregledanih: 0, zadnjih_24h: 0, meja_24h: 3, items: [] };
      await okno10.naloziNujnoPas();
      assert($10("nujno_pas").skrit === true && $10("nujno_pas").children.length === 0, "nujno.js: brez nujnih dejanj ni pasu");
      seznam10 = { nepregledanih: 2, zadnjih_24h: 2, meja_24h: 3, items: [postavka10(1), postavka10("2<img src=x onerror=alert(1)>", { dejanje: ZLO7[1], spremembe: "ni objekt", prej: [1], mail: ZLO7[0] })] };
      await okno10.naloziNujnoPas();
      const p10 = oznake($10("nujno_pas"));
      assert($10("nujno_pas").skrit === false, "nujno.js: z nujnimi dejanji je pas viden");
      assert(p10.elementi.length > 20 && p10.elementi.every((t) => DOV10.has(t)), "nujno.js: nobenega elementa iz podatkov (img/script/a/iframe) — seja ni povezava", [...new Set(p10.elementi)]);
      assert(brezOn(p10), "nujno.js: brez on* atributov");
      const bes10 = p10.besedila.join("\n");
      for (const z of ZLO7) assert(bes10.includes(z), "nujno.js: niz iz podatkov konča kot besedilo: " + z.slice(0, 30));
      assert(bes10.includes("javascript:alert(1)//") && bes10.includes("nujnem načinu") && bes10.includes("Pregledal sem") && bes10.includes("2 od 3"), "nujno.js: seja kot besedilo, naslov pasu, meja 24 h");
      const vlogaAlert = []; sprehod($10("nujno_pas"), (e) => { if (e.nodeType === 1 && e.attrs && e.attrs.role === "alert") vlogaAlert.push(e); });
      assert(vlogaAlert.length === 1, "nujno.js: pas ima role=alert");
      const tipke10 = () => { const r = []; sprehod($10("nujno_pas"), (e) => { if (e.nodeType === 1 && e.tagName === "button" && e.children.map((c) => c.data || "").join("") === "Pregledal sem") r.push(e); }); return r; };
      assert(tipke10().length === 2, "nujno.js: »Pregledal sem« pri vsakem nujnem dejanju posebej", tipke10().length);
      // Pregledal sem: Prekliči v oknu = brez POST-a; potrditev = POST z razlogom, nato osvežitev
      potrdiOdgovor10 = null; klici10.length = 0;
      await tipke10()[0].onclick();
      assert(potrdiKlici10.length === 1 && !klici10.some((k) => k.metoda === "POST"), "nujno.js: Prekliči v potrditvenem oknu = brez POST-a");
      const okvir10 = new El2("div"); okvir10.append(...potrdiKlici10[0].vsebina.filter(Boolean));
      const v10 = oznake(okvir10);
      assert(v10.elementi.every((t) => DOV10.has(t)) && v10.besedila.join(" ").includes(ZLO7[2]) && v10.besedila.join(" ").includes("prekliči žeton"), "nujno.js: potrditveno okno kaže citat kot besedilo in kaj narediti, če ni tvoj", [...new Set(v10.elementi)]);
      potrdiOdgovor10 = { razlog: "res sem potrdil" }; klici10.length = 0;
      seznam10 = { nepregledanih: 0, zadnjih_24h: 2, meja_24h: 3, items: [] };
      await tipke10()[0].onclick();
      const post10 = klici10.find((k) => k.metoda === "POST");
      assert(post10 && post10.pot === "/admin/api/predlogi/1/nujno-pregledano" && post10.telo.reason === "res sem potrdil" && klici10.some((k) => k.metoda === "GET"), "nujno.js: Pregledal sem -> POST /:id/nujno-pregledano, nato osvežitev", klici10);
      assert($10("nujno_pas").skrit === true, "nujno.js: ko ni več nepregledanih, pas izgine");
      // index.html: pas je na vrhu panela (pred meniji), naloži se ob Pregledu
      assert(/<div id="panel" class="skrito">\s*<!--[^>]*-->\s*<div id="nujno_pas" class="skrito"><\/div>\s*<nav>/.test(html), "index.html: rdeč pas na vrhu panela, pred menijem");
      assert(/window\.naloziNujnoPas\(\)/.test(skripta), "index.html: Pregled naloži rdeč pas");
    }
  }


  // --- 8. nov-dogodek.js (#328, 23. 10. 2026): »Nov dogodek«, nalaganje plakata, »Pred objavo«, »Podvoji« v lazni strani ---
  {
    class El8 extends El { get classList() { return { add() {}, remove() {}, toggle() {}, contains: () => false }; } removeAttribute(k) { delete this.attrs[k]; } click() {} }
    const el8 = {};
    const $8 = (id) => (id === "dg_nov" ? null : (el8[id] = el8[id] || new El8("div")));   // kot document.getElementById: gumba »Nov dogodek« se ni
    const brezOn = (p) => !p.elementi.some(t => t.startsWith("atribut:"));
    const doc8 = { createElement: (t) => new El8(t), createTextNode: (t) => new Besedilo(t), readyState: "complete", addEventListener() {} };
    const klici8 = [], zgod8 = [], zavihki8 = [], obv8 = [];
    let odg8 = {}, potrdi8 = [];
    const klic8 = async (metoda, pot, telo) => {
      klici8.push([metoda, pot, telo]);
      const k = Object.keys(odg8).find(x => pot.startsWith(x) && (odg8[x].metoda || metoda) === metoda);
      mora(k, "nepričakovan klic API-ja iz nov-dogodek.js: " + metoda + " " + pot);
      if (odg8[k].napaka) throw new Error(odg8[k].napaka);
      return JSON.parse(JSON.stringify(odg8[k].telo));
    };
    const okno8 = {};
    new Function("window", "document", "$", "h", "klic", "datum", "obvesti", "potrdi", "pokaziZavihek", "history", "createImageBitmap", "FormData", "fetch", fs.readFileSync(path.join(__dirname, "..", "admin", "nov-dogodek.js"), "utf8"))(
      okno8, doc8, $8, new Function("document", `${mh[0]}\nreturn h;`)(doc8), klic8, new Function(`${md[0]}\nreturn datum;`)(), (b, v) => obv8.push([b, v]),
      async (o) => { const f = potrdi8.shift(); mora(f, "nepričakovano potrditveno okno: " + o.naslov); return f(o); }, (z) => zavihki8.push(z), { pushState: (...a) => zgod8.push(a) }, undefined, undefined, undefined);
    const nv = okno8.novDogodek;
    mora(nv && ["zaUrejevalnik", "objavaBlokirana", "vstaviGumb", "novDogodek", "podvoji"].every(k => typeof nv[k] === "function"), "nov-dogodek.js ne izvozi window.novDogodek");
    const DOV8 = new Set(["div", "span", "b", "a", "h2", "p", "button", "input", "select", "option", "label"]);
    const idje = (e, id) => e.id === id || (e.attrs && e.attrs.id === id);
    const najdi = (koren, f) => { const r = []; sprehod(koren, (e) => { if (e.nodeType === 1 && f(e)) r.push(e); }); return r; };
    const poId = (koren, id) => najdi(koren, (e) => idje(e, id))[0];

    // gumb »Nov dogodek« v glavi seznama
    const starsi = new El8("span"); let vstavljen = null;
    starsi.insertBefore = (n) => { vstavljen = n; };
    const osvezi8 = new El8("button"); osvezi8.parentNode = starsi; el8.dg_osvezi = osvezi8;
    nv.vstaviGumb();
    assert(vstavljen && vstavljen.tagName === "button" && vstavljen.textContent === "Nov dogodek" && typeof vstavljen.onclick === "function", "nov-dogodek.js: gumb »Nov dogodek« se vstavi v glavo seznama");

    // urejevalnik osnutka: pregled pred objavo
    const ZLO8 = ['<img src=x onerror=alert("a")>', "<script>alert('b')</script>", "</div><iframe src=javascript:alert(1)>"];
    el8.dge_objavi = new El8("button"); el8.dge_gumbi = new El8("div"); el8.dge_razsiritve = new El8("div"); el8.dge_plakat_orodja = new El8("div");
    odg8 = { "/admin/api/opozorila?dogodek=": { telo: { items: [
      { vrsta: "prodajalec_nepopoln", resnost: "rdece", cilj_tip: "dogodek", cilj_id: 12, besedilo: ZLO8[0] },
      { vrsta: "neznana_vrsta", resnost: "oranzno", cilj_tip: "dogodek", cilj_id: 12, besedilo: ZLO8[1] + " " + ZLO8[2] },
      { vrsta: "brez_konca", resnost: ZLO8[0], cilj_tip: "dogodek", cilj_id: 12, besedilo: "x" }], stevci: { rdece: 1, oranzno: 1, rumeno: 0 } } } };
    nv.zaUrejevalnik({ event: { id: 12, status: "draft", title: ZLO8[0], start_at: "2030-01-01T10:00:00Z" } });
    assert(el8.dge_objavi.disabled === true && nv.objavaBlokirana(12) === true, "nov-dogodek.js: med preverjanjem je Objavi onemogočen (fail-safe)");
    await new Promise(r => setImmediate(r));
    const pr = pregled($8("dge_razsiritve")), pbes = pr.besedila.join("\n");
    assert(pr.elementi.every(t => DOV8.has(t)) && brezOn(pr), "nov-dogodek.js: pregled pred objavo nima elementov iz podatkov in on* atributov", [...new Set(pr.elementi)]);
    assert(pbes.includes(ZLO8[1]) && pbes.includes("Podatki prodajalca kluba niso popolni") && pbes.includes("Ovira:"), "nov-dogodek.js: besedilo neznane vrste iz podatkov konča kot besedilo, znana vrsta ima slovensko besedilo");
    assert(el8.dge_objavi.disabled === true && nv.objavaBlokirana(12) === true, "nov-dogodek.js: rdeča ovira: Objavi onemogočen");
    assert(klici8.some(k => k[1] === "/admin/api/opozorila?dogodek=12"), "nov-dogodek.js: klic ?dogodek=12");
    odg8 = { "/admin/api/opozorila?dogodek=": { telo: { items: [], stevci: { rdece: 0, oranzno: 0, rumeno: 0 } } } };
    najdi($8("dge_razsiritve"), e => idje(e, "dge_preveri_znova"))[0].onclick(); await new Promise(r => setImmediate(r));
    assert(el8.dge_objavi.disabled === false && nv.objavaBlokirana(12) === false && pregled($8("dge_razsiritve")).besedila.join("\n").includes("Vse je v redu"), "nov-dogodek.js: brez opozoril: Objavi omogočen");
    odg8 = { "/admin/api/opozorila?dogodek=": { napaka: "503: busy" } };
    najdi($8("dge_razsiritve"), e => idje(e, "dge_preveri_znova"))[0].onclick(); await new Promise(r => setImmediate(r));
    assert(nv.objavaBlokirana(12) === true && el8.dge_objavi.disabled === true, "nov-dogodek.js: pregled ni uspel: Objavi ostane onemogočen");
    // »Preveri znova« je med preverjanjem onemogocen; ob rdeci oviri / napaki je »Objavi vseeno«
    odg8 = { "/admin/api/opozorila?dogodek=": { telo: { items: [{ vrsta: "prodajalec_nepopoln", resnost: "rdece", cilj_tip: "dogodek", cilj_id: 12, besedilo: "x" }], stevci: { rdece: 1, oranzno: 0, rumeno: 0 } } },
      "/admin/api/events/12": { metoda: "PATCH", telo: { id: 12, status: "published" } } };
    let osvezeno8 = 0;
    nv.zaUrejevalnik({ event: { id: 12, status: "draft", title: ZLO8[0], start_at: "2030-01-01T10:00:00Z" }, osvezi: () => { osvezeno8++; } });
    assert(najdi($8("dge_razsiritve"), e => idje(e, "dge_preveri_znova"))[0].disabled === true && najdi($8("dge_razsiritve"), e => idje(e, "dge_objavi_vseeno")).length === 0, "nov-dogodek.js: med preverjanjem je »Preveri znova« onemogocen in »Objavi vseeno« ni");
    await new Promise(r => setImmediate(r));
    assert(najdi($8("dge_razsiritve"), e => idje(e, "dge_preveri_znova"))[0].disabled === false, "nov-dogodek.js: po preverjanju je »Preveri znova« spet omogocen");
    const vseeno = najdi($8("dge_razsiritve"), e => idje(e, "dge_objavi_vseeno"));
    assert(vseeno.length === 1 && vseeno[0].textContent === "Objavi vseeno", "nov-dogodek.js: ob rdeci oviri je sekundarni gumb »Objavi vseeno«");
    let potrdiO = null;
    potrdi8 = [async (o) => { potrdiO = o; return { razlog: "Martin je potrdil po telefonu" }; }];
    klici8.length = 0;
    await vseeno[0].onclick();
    assert(potrdiO && potrdiO.vpis === "OBJAVI" && potrdiO.razlog === "obvezen" && potrdiO.nevarno === true, "nov-dogodek.js: »Objavi vseeno«: potrdi() z vpisom OBJAVI, obveznim razlogom in nevarno", potrdiO && { vpis: potrdiO.vpis, razlog: potrdiO.razlog });
    const pat = klici8.find(k => k[0] === "PATCH");
    assert(pat && pat[1] === "/admin/api/events/12" && JSON.stringify(pat[2]) === JSON.stringify({ status: "published", reason: "Martin je potrdil po telefonu" }) && osvezeno8 === 1, "nov-dogodek.js: PATCH /admin/api/events/12 { status: published, reason } in ponovno nalaganje", pat);
    potrdi8 = [async () => null]; klici8.length = 0;
    await najdi($8("dge_razsiritve"), e => idje(e, "dge_objavi_vseeno"))[0].onclick();
    assert(!klici8.some(k => k[0] === "PATCH"), "nov-dogodek.js: preklic okna ne objavi");
    odg8 = { "/admin/api/opozorila?dogodek=": { napaka: "503: busy" } };
    nv.zaUrejevalnik({ event: { id: 14, status: "cancelled", title: "Odpovedan", start_at: "2030-01-01T10:00:00Z" } }); await new Promise(r => setImmediate(r));
    assert(nv.objavaBlokirana(14) === true && najdi($8("dge_razsiritve"), e => idje(e, "dge_objavi_vseeno")).length === 1, "nov-dogodek.js: odpovedan dogodek ima tudi pregled in zaklep Objavi; ob napaki pregleda je »Objavi vseeno«");
    let potrdiC = null; potrdi8 = [async (o) => { potrdiC = o; return null; }];
    await najdi($8("dge_razsiritve"), e => idje(e, "dge_objavi_vseeno"))[0].onclick();
    assert(potrdiC && potrdiC.nevarno === true && pregled({ children: [].concat(potrdiC.vsebina).filter(y => y && y.nodeType), nodeType: 1, tagName: "x", attrs: {} }).besedila.join(" ").includes("Dogodek je bil odpovedan; kupci so morda že dobili vračila. Ponovna objava obvesti sledilce."),
      "nov-dogodek.js: »Objavi vseeno« pri odpovedanem dogodku: jasno opozorilo o vracilih in sledilcih");
    potrdiC = null; potrdi8 = [async (o) => { potrdiC = o; return null; }];
    nv.zaUrejevalnik({ event: { id: 15, status: "draft", title: "Osnutek", start_at: "2030-01-01T10:00:00Z" } }); await new Promise(r => setImmediate(r));
    await najdi($8("dge_razsiritve"), e => idje(e, "dge_objavi_vseeno"))[0].onclick();
    assert(potrdiC && !pregled({ children: [].concat(potrdiC.vsebina).filter(y => y && y.nodeType), nodeType: 1, tagName: "x", attrs: {} }).besedila.join(" ").includes("odpovedan"), "nov-dogodek.js: pri osnutku opozorila o odpovedi ni");
    nv.zaUrejevalnik({ event: { id: 13, status: "published", title: "x", start_at: "2030-01-01T10:00:00Z" } });
    assert(nv.objavaBlokirana(13) === false && $8("dge_razsiritve").children.length === 0, "nov-dogodek.js: objavljen dogodek nima bloka Pred objavo in ni blokiran");
    assert(najdi($8("dge_gumbi"), e => idje(e, "dge_podvoji")).length >= 2, "nov-dogodek.js: gumb Podvoji pri vsakem odprtju urejevalnika (dogodki.js ustvari nov vsebnik)");

    // podvoji: rezultat s povezavami samo na #/dogodki/<stevilo>, naslovi kot besedilo
    el8.dge_razsiritve = new El8("div");
    odg8 = { "/admin/api/events/12/duplicate": { metoda: "POST", telo: { events: [{ id: 41, title: ZLO8[0], start_at: "2030-02-01T10:00:00Z", status: "draft" }, { id: "3<script>", title: ZLO8[1], start_at: "2030-02-08T10:00:00Z", status: "draft" }] } } };
    potrdi8 = [async (o) => { const sel = najdi(o.vsebina.flat ? { children: [].concat(o.vsebina).filter(x => x && x.nodeType), nodeType: 1, tagName: "x", attrs: {} } : o.vsebina, e => e.tagName === "select")[0]; sel.value = "1"; return { razlog: "" }; }];
    nv.zaUrejevalnik({ event: { id: 12, status: "published", title: "Izvor", start_at: "2030-01-01T10:00:00Z" } });
    klici8.length = 0;
    await nv.podvoji({ id: 12, status: "published", title: "Izvor", start_at: "2030-01-01T10:00:00Z" });
    const dup = klici8.find(k => /duplicate$/.test(k[1]));
    assert(dup && dup[2].ponovi === "weekly" && dup[2].n === 2 && typeof dup[2].startAt === "string" && Object.keys(dup[2]).sort().join() === "n,ponovi,startAt", "nov-dogodek.js: podvoji pošlje { startAt, ponovi: weekly, n = dodatni + 1 }", dup && dup[2]);
    const pp = pregled($8("dge_razsiritve")), ppbes = pp.besedila.join("\n");
    assert(pp.elementi.every(t => DOV8.has(t)) && brezOn(pp), "nov-dogodek.js: rezultat podvajanja nima elementov iz podatkov", [...new Set(pp.elementi)]);
    assert(ppbes.includes(ZLO8[0]) && ppbes.includes(ZLO8[1]), "nov-dogodek.js: naslovi podvojenih osnutkov so besedilo");
    const hrefi = najdi($8("dge_razsiritve"), e => e.tagName === "a").map(a => a.attrs.href);
    assert(JSON.stringify(hrefi) === JSON.stringify(["#/dogodki/41", "#/dogodki/0"]), "nov-dogodek.js: povezave samo #/dogodki/<celo število> (id iz podatkov, ki ni število, postane 0)", hrefi);
    najdi($8("dge_razsiritve"), e => e.tagName === "a")[0].onclick({ preventDefault() {} });
    assert(zgod8[zgod8.length - 1][2] === "#/dogodki/41" && zavihki8[zavihki8.length - 1] === "dogodki", "nov-dogodek.js: klik na povezavo odpre osnutek");

    // nov dogodek: validacija pred klicem, nato POST /events s centi in koncem +6 h
    odg8 = { "/admin/api/clubs": { metoda: "GET", telo: [{ id: 6, name: ZLO8[0], city: "LJ", hidden: false, is_organizer: false, is_demo: false }, { id: "x<", name: "napacen" }] },
      "/admin/api/events": { metoda: "POST", telo: { id: 9, title: "Moj dogodek" } } };
    const zacetek8 = new Date(Date.now() + 5 * 864e5); zacetek8.setSeconds(0, 0);
    const lok8 = (() => { const q = (n) => String(n).padStart(2, "0"); return `${zacetek8.getFullYear()}-${q(zacetek8.getMonth() + 1)}-${q(zacetek8.getDate())}T${q(zacetek8.getHours())}:${q(zacetek8.getMinutes())}`; })();
    const polni = (o, v) => { for (const [id, x] of Object.entries(v)) { const e = poId({ children: [].concat(o.vsebina).filter(y => y && y.nodeType), nodeType: 1, tagName: "x", attrs: {} }, id); mora(e, "polje " + id + " ni v oknu Nov dogodek"); e.value = x; } };
    potrdi8 = [async () => ({ razlog: "" }), async (o) => { polni(o, { nd_klub: "6", nd_naslov: "  Moj dogodek ", nd_zacetek: lok8, nd_cena: "12,5", nd_kap: "250" }); return { razlog: "" }; }];
    klici8.length = 0; obv8.length = 0; zgod8.length = 0;
    await nv.novDogodek();
    const kopt = klici8.find(k => k[1] === "/admin/api/events");
    assert(obv8.some(o => o[0] === "Izberi klub." && o[1] === "slabo") && klici8.filter(k => k[1] === "/admin/api/events").length === 1, "nov-dogodek.js: prazen obrazec: napaka, brez klica; okno se znova odpre");
    assert(kopt && kopt[2].clubId === 6 && kopt[2].title === "Moj dogodek" && kopt[2].status === "draft" && kopt[2].ticketPriceCents === 1250 && kopt[2].capacity === 250 &&
      Date.parse(kopt[2].endAt) - Date.parse(kopt[2].startAt) === 6 * 3600e3 && Date.parse(kopt[2].startAt) === zacetek8.getTime(), "nov-dogodek.js: POST /admin/api/events (ne /events): draft, 1250 centov (ne plavajoča vejica), konec = začetek + 6 h", kopt && kopt[2]);
    assert(zgod8.length === 1 && zgod8[0][2] === "#/dogodki/9" && zavihki8[zavihki8.length - 1] === "dogodki", "nov-dogodek.js: po uspehu se odpre urejevalnik #/dogodki/9");
    const optKlubi = [];
    // vrednosti kluba v izbiri: samo številke (id '"x<"' je izločen), ime kot besedilo
    potrdi8 = [async (o) => { sprehod({ children: [].concat(o.vsebina).filter(y => y && y.nodeType), nodeType: 1, tagName: "x", attrs: {} }, e => { if (e.nodeType === 1 && e.tagName === "option") optKlubi.push([e.attrs.value, e.textContent]); }); return null; }];
    await nv.novDogodek();
    assert(optKlubi.length === 2 && optKlubi[1][0] === "6" && optKlubi[1][1].includes(ZLO8[0]), "nov-dogodek.js: izbira kluba: id kot število, ime kot besedilo, neveljaven id izločen", optKlubi);

    // parametri podpisa (pogodba z backendom/spletom): camelCase -> snake_case, nepodpisano izpuščeno
    const pod = nv.parametriPodpisa({ timestamp: 1, signature: "s", apiKey: "k", cloudName: "c", folder: "outly", publicId: "outly/u1/x", allowedFormats: ["jpg", "png"], nic: null });
    assert(JSON.stringify(pod) === JSON.stringify({ timestamp: "1", folder: "outly", public_id: "outly/u1/x", allowed_formats: "jpg,png" }), "nov-dogodek.js: parametriPodpisa: vsa podpisana polja, snake_case, brez signature/apiKey/cloudName", pod);
  }

  // --- 9. mnozicno.js (#329, 23. 10. 2026): mnozicna dejanja nad dogodki v lazni strani ---
  {
    class El9 extends El { get classList() { return { add() {}, remove() {}, toggle() {}, contains: () => false }; } }
    const doc9 = { createElement: (t) => new El9(t), createTextNode: (t) => new Besedilo(t) };
    const h9 = new Function("document", `${mh[0]}\nreturn h;`)(doc9);
    const klici9 = [], obv9 = [];
    let odg9 = null, potrdi9 = [];
    const klic9 = async (metoda, pot, telo) => { klici9.push([metoda, pot, telo]); mora(odg9, "nepričakovan klic API-ja iz mnozicno.js: " + metoda + " " + pot); if (odg9.napaka) throw new Error(odg9.napaka); return JSON.parse(JSON.stringify(odg9.telo)); };
    const okno9 = {};
    new Function("window", "h", "klic", "varno", "obvesti", "potrdi", fs.readFileSync(path.join(__dirname, "..", "admin", "mnozicno.js"), "utf8"))(
      okno9, h9, klic9, async (fn) => { try { await fn(); } catch (e) { obv9.push([e.message, "slabo"]); } }, (b, v) => obv9.push([b, v]),
      async (o) => { const f = potrdi9.shift(); mora(f, "nepričakovano potrditveno okno: " + o.naslov); return f(o); });
    const mn = okno9.mnozicno;
    mora(mn && ["zaSeznam", "zamikIzDni", "izvedi"].every(k => typeof mn[k] === "function"), "mnozicno.js ne izvozi window.mnozicno");
    const DOV9 = new Set(["div", "span", "b", "p", "ul", "li", "button", "input", "label", "table", "thead", "tbody", "tr", "th", "td"]);
    const najdi9 = (koren, f) => { const r = []; sprehod(koren, (e) => { if (e.nodeType === 1 && f(e)) r.push(e); }); return r; };
    const ZLO9 = ['<img src=x onerror=alert("a")>', "<script>alert('b')</script>", '"><svg onload=alert(1)>'];

    // zamik: dnevi -> minute
    const zam = { "7": 10080, "-1": -1440, "0,5": 720, "0.5": 720, " 30 ": 43200, "-30": -43200 };
    assert(Object.entries(zam).every(([v, m]) => mn.zamikIzDni(v) === m), "mnozicno.js: premik v dneh -> minute (7, -1, 0,5, 30)", Object.entries(zam).map(([v]) => [v, mn.zamikIzDni(v)]));
    assert(["", "0", "abc", "31", "-30,5", "1e3", "7 dni", null, undefined, "0,0001", "1000"].every(v => mn.zamikIzDni(v) === null), "mnozicno.js: neveljaven premik (0, nad 30 dni, nestevilo) = null");

    // tabela kot jo narise dogodki.js
    const dogodki9 = [{ id: 11, title: ZLO9[0], status: "published" }, { id: 12, title: ZLO9[1], status: "draft" }, { id: "13<x", title: ZLO9[2], status: "published" }];
    const odprta9 = [];
    const vrstice9 = dogodki9.map((x) => { const tr = h9("tr", { class: "dg-vrstica" }, h9("td", {}, String(x.title))); tr.onclick = () => odprta9.push(x.id); return tr; });
    const vsebnik9 = new El9("div");
    let osvezeno9 = 0;
    const narisi9 = () => { vsebnik9.replaceChildren(h9("table", { class: "dg-tabela" }, h9("thead", {}, h9("tr", {}, h9("th", {}, "#"))), h9("tbody", {}, vrstice9))); };
    narisi9();
    mn.zaSeznam({ vsebnik: vsebnik9, dogodki: dogodki9, osvezi: () => { osvezeno9++; } });
    const p9 = pregled(vsebnik9);
    assert(p9.elementi.every(t => DOV9.has(t)) && !p9.elementi.some(t => t.startsWith("atribut:")), "mnozicno.js: seznam s kljukicami nima elementov iz podatkov in on* atributov", [...new Set(p9.elementi)]);
    const kljukice9 = najdi9(vsebnik9, e => e.tagName === "input" && e.attrs.type === "checkbox");
    assert(kljukice9.length === 4, "mnozicno.js: kljukica v glavi (izberi vse) + ena na vrstico", kljukice9.length);
    assert(najdi9(vsebnik9, e => e.tagName === "tr").slice(1).every(tr => tr.children[0].tagName === "td" && tr.children[0].children[0].tagName === "input"), "mnozicno.js: kljukica je prvi stolpec vsake vrstice");
    assert(najdi9(vsebnik9, e => e.tagName === "div" && e.attrs.id === "mn_trak").length === 1 && vsebnik9.children[0].attrs.id === "mn_trak", "mnozicno.js: vrstica dejanj je pred tabelo, brez izbire prazna", vsebnik9.children[0].children.length);
    const td1 = vsebnik9.children[1].children[1].children[0].children[0];
    let ustavljeno = 0;
    td1.onclick({ stopPropagation() { ustavljeno++; } }); td1.onkeydown({ stopPropagation() { ustavljeno++; } });
    assert(ustavljeno === 2 && odprta9.length === 0, "mnozicno.js: klik in tipka na kljukici ne odpreta urejevalnika (stopPropagation)");

    // izbira dveh dogodkov -> vrstica dejanj
    const vrsta9 = () => vsebnik9.children[0];
    const polje9 = (i) => najdi9(vsebnik9, e => e.tagName === "tr").slice(1)[i].children[0].children[0];
    polje9(0).checked = true; polje9(0).onchange(); polje9(1).checked = true; polje9(1).onchange();
    const trakP = pregled(vrsta9());
    assert(trakP.besedila.join(" ").includes("Izbranih: 2") && najdi9(vrsta9(), e => e.tagName === "button").map(b => b.textContent).join("|") === "Ustavi prodajo|Zaženi prodajo|Med osnutke|Prestavi|Počisti izbiro",
      "mnozicno.js: vrstica dejanj: Izbranih 2 in gumbi Ustavi/Zaženi/Med osnutke/Prestavi/Počisti", trakP.besedila);
    const gumb9 = (ime) => najdi9(vrsta9(), e => e.tagName === "button" && e.textContent === ime)[0];

    // preklic potrditve: brez klica
    let ponudba = null;
    potrdi9 = [async (o) => { ponudba = o; return null; }];
    await gumb9("Ustavi prodajo").onclick();
    const vsebinaP = pregled({ children: [].concat(ponudba.vsebina).filter(y => y && y.nodeType), nodeType: 1, tagName: "x", attrs: {} });
    assert(ponudba.razlog === "obvezen" && ponudba.nevarno === true && vsebinaP.besedila.join("\n").includes(ZLO9[0]) && vsebinaP.besedila.join("\n").includes(ZLO9[1]) && vsebinaP.elementi.every(t => DOV9.has(t) || t === "x") &&
      !vsebinaP.elementi.some(t => t.startsWith("atribut:")), "mnozicno.js: potrdi() ima obvezen razlog in seznam izbranih naslovov kot besedilo", { razlog: ponudba.razlog, nevarno: ponudba.nevarno });
    assert(klici9.length === 0, "mnozicno.js: preklic potrditve ne klice API-ja");

    // izvedba: pravo telo; rezultat po dogodkih; uspeli dogodki iz izbire, neuspeli ostanejo
    odg9 = { telo: { dejanje: "pause", results: [{ id: 11, ok: true, spremenjeno: true }, { id: 12, ok: false, napaka: "<b onclick=1>neznana</b>", status: 409, message: ZLO9[2] }] } };
    potrdi9 = [async () => ({ razlog: "Razlog: <i>plakat</i>" })];
    await gumb9("Ustavi prodajo").onclick();
    assert(klici9.length === 1 && klici9[0][0] === "POST" && klici9[0][1] === "/admin/api/events/bulk" && JSON.stringify(klici9[0][2]) === JSON.stringify({ ids: [11, 12], dejanje: "pause", razlog: "Razlog: <i>plakat</i>" }),
      "mnozicno.js: POST /admin/api/events/bulk { ids, dejanje, razlog } (brez zamik_min)", klici9[0]);
    const rP = pregled(vsebnik9.children[0]), rBes = rP.besedila.join("\n");
    assert(rP.elementi.every(t => DOV9.has(t)) && !rP.elementi.some(t => t.startsWith("atribut:")), "mnozicno.js: rezultat po dogodkih nima elementov iz podatkov", [...new Set(rP.elementi)]);
    assert(rBes.includes("uspelo 1, napak 1") && rBes.includes(ZLO9[0]) && rBes.includes(ZLO9[1]) && rBes.includes(ZLO9[2]), "mnozicno.js: rezultat: povzetek, naslovi in sporočilo API-ja (neznana koda) kot BESEDILO", rBes);
    assert(osvezeno9 === 1 && najdi9(vsebnik9, e => e.tagName === "button" && e.textContent === "Počisti izbiro").length === 1 && rBes.includes("Izbranih: 1"), "mnozicno.js: seznam se osveži, v izbiri ostane samo neuspeli dogodek");

    // Prestavi: neveljaven premik ponovno odpre okno z ohranjenim vnosom, veljaven gre v minutah
    const vnosPrestavi = (v) => async (o) => { const vnos = najdi9({ children: [].concat(o.vsebina).filter(y => y && y.nodeType), nodeType: 1, tagName: "x", attrs: {} }, e => e.attrs.id === "mn_zamik")[0]; mora(vnos, "polje premika v oknu Prestavi"); vnos.value = v; return { razlog: "Gostitelj je prestavil" }; };
    odg9 = { telo: { dejanje: "reschedule", results: [{ id: 12, ok: false, napaka: "has_sales", status: 409, message: "x" }] } };
    potrdi9 = [vnosPrestavi("abc"), vnosPrestavi("0"), vnosPrestavi("0,5")];
    klici9.length = 0; obv9.length = 0;
    await gumb9("Prestavi").onclick();
    assert(obv9.filter(o => o[1] === "slabo" && /Premik/.test(o[0])).length === 2 && potrdi9.length === 0, "mnozicno.js: dvakrat neveljaven premik: dve opozorili, okno se znova odpre", obv9);
    assert(klici9.length === 1 && klici9[0][2].dejanje === "reschedule" && klici9[0][2].zamik_min === 720 && klici9[0][2].razlog === "Gostitelj je prestavil" && JSON.stringify(klici9[0][2].ids) === "[12]", "mnozicno.js: Prestavi: zamik_min v minutah (0,5 dneva = 720)", klici9[0]);
    assert(vsebnik9.children[0].textContent.includes("ima prodane vstopnice") && vsebnik9.children[0].textContent.includes("Izbranih: 1"), "mnozicno.js: 409 has_sales ima slovensko razlago in dogodek ostane izbran");

    // napaka klica (npr. 429): opozorilo, izbira ostane
    odg9 = { napaka: "Too many requests. Please try again later." };
    potrdi9 = [async () => ({ razlog: "Spet" })];
    obv9.length = 0;
    await gumb9("Zaženi prodajo").onclick();
    assert(obv9.some(o => o[1] === "slabo" && /Too many/.test(o[0])) && vsebnik9.children[0].textContent.includes("Izbranih: 1"), "mnozicno.js: napaka API-ja (429): opozorilo, izbira ostane");

    // izberi vse: največ 50
    const veliko = Array.from({ length: 60 }, (_, i) => ({ id: 100 + i, title: "D" + i, status: "draft" }));
    vrstice9.length = 0;
    for (const x of veliko) { const tr = h9("tr", {}, h9("td", {}, x.title)); vrstice9.push(tr); }
    narisi9();
    obv9.length = 0;
    mn.zaSeznam({ vsebnik: vsebnik9, dogodki: veliko, osvezi: () => {} });
    const glavna9 = najdi9(vsebnik9, e => e.tagName === "th")[0].children[0];
    glavna9.checked = true; glavna9.onchange();
    assert(vsebnik9.children[0].textContent.includes("Izbranih: 50") && obv9.some(o => /50/.test(o[0])), "mnozicno.js: »izberi vse« izbere največ 50 in to pove");
    polje9(55).checked = true; polje9(55).onchange();
    assert(polje9(55).checked === false && obv9.filter(o => /največ 50/.test(o[0])).length >= 1 && vsebnik9.children[0].textContent.includes("Izbranih: 50"), "mnozicno.js: 51. kljukica ni mogoča");
    // po novem izrisu (filter) izbira velja samo za vidne dogodke
    narisi9(); mn.zaSeznam({ vsebnik: vsebnik9, dogodki: veliko.slice(0, 5), osvezi: () => {} });
    assert(vsebnik9.children[0].textContent.includes("Izbranih: 5"), "mnozicno.js: po zoženju filtra ostanejo izbrani samo vidni dogodki", vsebnik9.children[0].textContent);
  }

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
