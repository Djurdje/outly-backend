// Admin panel na telefonu (#328, PR 10, 23. 10. 2026): spodnja vrstica 5 zavihkov (Danes, Dogodki, Opozorila, Ljudje, Vec) namesto vrste gumbov.
// »Ljudje« (Prosnje, Klubi, Uporabniki) in »Vec« (ostalo, vkljucno s »Caka potrditev« in »Agent«) odpreta listo izbir nad vrstico.
// Vrstica je vidna samo pod 640 px (telefon.css); nad tem ostane navigacija z gumbi, ki je edini vir resnice: vrstica samo klikne ustrezen gumb v <nav>
// (pokaziZavihek, nalozi in napisi pri gumbih ostanejo en sam kos kode) in zrcali njihove znacke (stevilke) ter aktivni zavihek.
// Uporablja globalno h() iz index.html. DOM samo prek h()/textContent. Brez ogrodja in brez gradnje (DECISIONS 21. 10. 2026).
(function () {
  "use strict";
  // h() je deklarirana v inline skripti za tem modulom: zagon sele po razclenitvi strani (DOMContentLoaded), ne ob nalaganju datoteke.
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", zagon); else zagon();
  function zagon() {
  const panel = document.getElementById("panel");
  const nav = panel && panel.querySelector("nav");
  if (!panel || !nav || typeof h !== "function") return;

  // Skupine: kljuc = data-z gumba v <nav>; znacka = id elementa .n v tem gumbu.
  const LJUDJE = [["prosnje", "Prošnje", ["nProsenj"]], ["klubi", "Klubi", []], ["uporabniki", "Uporabniki", []]];
  const VEC = [["predlogi", "Čaka potrditev", ["nPredlogov"]], ["agent", "Agent", []], ["prijave", "Reports", ["nPrijav"]], ["vracila", "Vračila in spori", ["nVracil"]],
    ["finance", "Finance", []], ["promo", "Promo kode", []], ["guest", "Guest lists", []], ["pomoc", "Pomoč – odzivi", []]];
  // Ikone so CSS maske (telefon.css, .ikona.i-<ime>): v kodi ni znakov ali SVG nizov, samo ime ikone.
  const GLAVNI = [["pregled", "Danes", "danes", ["pregled"]], ["dogodki", "Dogodki", "dogodki", ["dogodki"]], ["opozorila", "Opozorila", "opozorila", ["opozorila"], ["nOpozorila"]]];
  const kljuci = (s) => s.map((x) => x[0]);

  const gumbNav = (z) => nav.querySelector(`button[data-z="${z}"]`);
  const aktivenZ = () => { const a = nav.querySelector('button[aria-current="page"]'); return a ? a.dataset.z : ""; };
  const stevilo = (ids) => ids.reduce((s, id) => { const e = document.getElementById(id); return s + (e && !e.classList.contains("skrito") ? (parseInt(e.textContent, 10) || 0) : 0); }, 0);

  const znacka = () => h("span", { class: "n skrito" });
  const vrstica = h("div", { id: "spodnja_vrstica", role: "navigation", "aria-label": "Glavni zavihki" });
  const ozadje = h("div", { id: "lista_ozadje", class: "skrito" });
  const lista = h("div", { id: "lista", class: "skrito", role: "dialog", "aria-label": "Zavihki" });
  let odprta = "";   // "" | "ljudje" | "vec"

  const tipke = {};   // ime -> { gumb, znacka, skupina }
  function dodajTipko(ime, besedilo, ikona, skupina, ids, izbira) {
    const zn = znacka();
    const g = h("button", { type: "button", "data-t": ime, "aria-label": besedilo }, h("span", { class: "ikona i-" + ikona, "aria-hidden": "true" }), h("span", {}, besedilo), zn);
    g.onclick = izbira;
    tipke[ime] = { gumb: g, znacka: zn, skupina, ids };
    vrstica.append(g);
  }
  function pojdi(z) {
    zapri();
    const g = gumbNav(z); if (g) g.click();
    // lista z izbrano tipko izgine: fokus ne sme ostati na izginulem elementu. Zavihek se ob nalaganju prerise (replaceChildren), zato fokus na njegovih
    // elementih ni stabilen; fokus dobi tipka vrstice, ki zavihku pripada (stabilen element).
    const t = Object.values(tipke).find((x) => x.skupina.includes(z));
    if (t) t.gumb.focus({ preventScroll: true });
  }
  function odpri(ime) {
    if (odprta === ime) { zapri(); return; }
    odprta = ime;
    const seznam = ime === "ljudje" ? LJUDJE : VEC;
    const trenutni = aktivenZ();
    lista.replaceChildren(
      h("h2", {}, ime === "ljudje" ? "Ljudje" : "Več"),
      h("div", { class: "izbire" }, seznam.map(([z, besedilo, ids]) => {
        const zn = znacka(); const n = stevilo(ids);
        if (n > 0) { zn.textContent = String(n); zn.classList.remove("skrito"); }
        const g = h("button", { type: "button", "data-z": z, class: z === trenutni ? "aktiven" : "" }, h("span", {}, besedilo), zn);
        g.onclick = () => pojdi(z);
        return g;
      })));
    lista.classList.remove("skrito"); ozadje.classList.remove("skrito");
    tipke[ime].gumb.setAttribute("aria-expanded", "true");
    const prvi = lista.querySelector("button"); if (prvi) prvi.focus();
  }
  function zapri() {
    if (!odprta) return;
    const ime = odprta; odprta = "";
    lista.classList.add("skrito"); ozadje.classList.add("skrito");
    tipke[ime].gumb.setAttribute("aria-expanded", "false");
  }

  for (const [z, besedilo, ikona, , ids] of GLAVNI) dodajTipko(z, besedilo, ikona, [z], ids || [], () => pojdi(z));
  dodajTipko("ljudje", "Ljudje", "ljudje", kljuci(LJUDJE), LJUDJE.flatMap((x) => x[2]), () => odpri("ljudje"));
  dodajTipko("vec", "Več", "vec", kljuci(VEC), VEC.flatMap((x) => x[2]), () => odpri("vec"));
  tipke.ljudje.gumb.setAttribute("aria-haspopup", "dialog"); tipke.vec.gumb.setAttribute("aria-haspopup", "dialog");

  function osvezi() {
    const a = aktivenZ();
    for (const t of Object.values(tipke)) {
      const je = t.skupina.includes(a);
      t.gumb.classList.toggle("aktiven", je);
      if (je) t.gumb.setAttribute("aria-current", "page"); else t.gumb.removeAttribute("aria-current");
      const n = stevilo(t.ids);
      t.znacka.textContent = n > 0 ? String(n) : ""; t.znacka.classList.toggle("skrito", !(n > 0));
    }
  }
  ozadje.onclick = zapri;
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && odprta) { const ime = odprta; zapri(); tipke[ime].gumb.focus(); } });
  // aktivni zavihek (aria-current) in znacke (besedilo/razred spanov .n) spreminjajo drugi deli panela: zrcalimo jih, ne podvajamo klicev API-ja
  new MutationObserver(osvezi).observe(nav, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["class", "aria-current"] });

  panel.append(ozadje, lista, vrstica);
  osvezi();

  // Rdeci pas nujnih dejanj agenta (nujno.js) stoji na vrhu strani. Ko ga drsenje odnese iz zaslona (ali je zavihek dolg), ostane viden ozek rdec trak,
  // ki z dotikom vrne na pas. Besedilo traku je besedilo naslova pasu (textContent), nic iz podatkov se ne vstavlja kot HTML.
  const pas = document.getElementById("nujno_pas");
  if (pas) {
    const trak = h("button", { id: "nujno_trak", type: "button" });
    pas.after(trak);
    trak.onclick = () => pas.scrollIntoView({ behavior: "smooth", block: "start" });
    let vPogledu = true;
    const pokazi = () => {
      const naslov = pas.querySelector(".nj-naslov b");
      const jePas = !pas.classList.contains("skrito") && !!naslov;
      if (jePas) trak.textContent = naslov.textContent;
      trak.classList.toggle("vidno", jePas && !vPogledu);
    };
    if (typeof IntersectionObserver === "function") new IntersectionObserver((v) => { vPogledu = v[v.length - 1].isIntersecting; pokazi(); }).observe(pas);
    new MutationObserver(pokazi).observe(pas, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
  }
  }
})();
