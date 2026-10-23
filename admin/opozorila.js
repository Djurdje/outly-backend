// Admin panel, zavihek »Opozorila« (#326, 23. 10. 2026): seznam opozoril po resnosti (GET /admin/api/opozorila) in seznam davcno potrjenih racunov po stanju
// (GET /admin/api/racuni; racuni v stanju »napaka« drugje v panelu niso vidni). Samo branje; ukrepi so v zavihkih Dogodki, Vracila in spori ali (racuni) rocni
// postopek v docs/STATE.md (migracija z Martinovim DA). Brez e-naslovov kupcev: strezniki jih ne vrnejo.
// Brez ogrodja in brez gradnje (DECISIONS 21. 10. 2026). Uporablja globalne funkcije iz index.html: klic, h, datum, $, obvesti, varno, pokaziZavihek.
// XSS: podatki v DOM SAMO prek h() / textContent; brez innerHTML z nizi in brez inline-atributov (onclick-nizov) (test_admin_xss.js preverja tudi ta modul).
(function () {
  "use strict";
  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);
  const RESNOSTI = [["rdece", "Rdeče", "slabo"], ["oranzno", "Oranžno", "opoz"], ["rumeno", "Rumeno", "rumena"]];
  const STANJA_RACUNOV = { caka: ["čaka", "opoz"], izdan: ["izdan", "siva"], potrjen: ["potrjen", "ok"], napaka: ["napaka", "slabo"], preklican: ["preklican", "siva"] };
  let racunFilter = "";
  let opozoriloStanje = null;

  function denar(c) {
    const x = cele(c), evri = String(Math.floor(Math.abs(x) / 100)).replace(/\B(?=(\d{3})+(?!\d))/g, ".");
    return (x < 0 ? "−" : "") + evri + "," + String(Math.abs(x) % 100).padStart(2, "0") + " €";
  }

  function naDogodek(id) {
    if (!Number.isSafeInteger(id) || id <= 0) return;
    history.pushState(null, "", "#/dogodki/" + id);
    pokaziZavihek("dogodki");
  }
  function naRacune(stanje) {
    racunFilter = STANJA_RACUNOV[stanje] ? stanje : "";
    naloziRacune();
    const koren = $("op_racuni");
    if (koren && koren.scrollIntoView) koren.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // kam vodi klik na opozorilo; null = ni cilja (postavka je samo informacija)
  function cilj(o) {
    if (o.cilj_tip === "dogodek" && Number.isSafeInteger(Number(o.cilj_id))) return { href: "#/dogodki/" + Number(o.cilj_id), pojdi: () => naDogodek(Number(o.cilj_id)) };
    if (o.cilj_tip === "racun") return { href: "#racuni", pojdi: () => naRacune("napaka") };
    if (o.cilj_tip === "racuni") return { href: "#racuni", pojdi: () => naRacune("caka") };
    if (o.cilj_tip === "vracila" || o.cilj_tip === "spori") return { href: "#vracila", pojdi: () => pokaziZavihek("vracila") };
    return null;
  }

  function vrstica(o) {
    const c = cilj(o);
    const znacka = (RESNOSTI.find((r) => r[0] === o.resnost) || [0, String(o.resnost), "siva"])[2];
    const vsebina = [
      h("span", { class: "op-pika " + znacka, "aria-hidden": "true" }),
      h("span", { class: "op-besedilo" }, o.besedilo),
      o.cas ? h("span", { class: "op-cas" }, datum(o.cas)) : null,
    ];
    return c
      ? h("a", { class: "op-vrstica", href: c.href, onclick: (ev) => { ev.preventDefault(); c.pojdi(); } }, vsebina)
      : h("div", { class: "op-vrstica brez-cilja" }, vsebina);
  }

  function narisiOpozorila(d) {
    const koren = $("op_opozorila");
    const stevci = d.stevci || {};
    const glava = h("h2", {}, "Opozorila",
      h("span", { class: "desno" },
        RESNOSTI.map(([k, ime, razred]) => h("span", { class: "znacka " + (razred === "rumena" ? "siva" : razred) }, `${ime.toLowerCase()} ${cele(stevci[k])}`)),
        h("button", { class: "tih mali", type: "button", onclick: naloziOpozorila }, "Osveži")));
    const telo = [];
    const items = Array.isArray(d.items) ? d.items : [];
    if (!items.length) telo.push(h("div", { class: "prazno" }, "Ni opozoril. Vse, kar nadzoruje panel, je v redu."));
    for (const [k, ime, razred] of RESNOSTI) {
      const del = items.filter((o) => o.resnost === k);
      if (!del.length) continue;
      telo.push(h("h3", { class: "dn-podnaslov" }, h("span", { class: "znacka " + (razred === "rumena" ? "siva" : razred) }, ime), ` ${cele(stevci[k])}`));
      telo.push(h("div", { class: "op-seznam" }, del.map(vrstica)));
    }
    const znane = RESNOSTI.map((r) => r[0]);
    const ostalo = items.filter((o) => !znane.includes(o.resnost));   // neznana resnost (novejsi backend): opozorilo se ne sme izgubiti
    if (ostalo.length) {
      telo.push(h("h3", { class: "dn-podnaslov" }, h("span", { class: "znacka siva" }, "Ostalo")));
      telo.push(h("div", { class: "op-seznam" }, ostalo.map(vrstica)));
    }
    if (items.length && cele(stevci.rdece) + cele(stevci.oranzno) + cele(stevci.rumeno) > items.length) {
      telo.push(h("div", { class: "opozorilo" }, `Prikazanih je prvih ${items.length} opozoril; števci zgoraj štejejo vsa.`));
    }
    koren.replaceChildren(h("div", { class: "skupina" }, glava, h("div", { class: "telo" }, telo)));
    const n = $("nOpozorila");
    if (n) { n.textContent = cele(stevci.rdece); n.classList.toggle("skrito", !cele(stevci.rdece)); }
  }

  function racunKartica(x) {
    const s = STANJA_RACUNOV[x.stanje] || [String(x.stanje), "siva"];
    const stevilka = x.ponudnik_stevilka || (x.stevilka !== null && x.stevilka !== undefined ? String(x.stevilka) : "—");
    return h("div", { class: "rc-kartica" },
      h("div", { class: "rc-glava" },
        h("b", {}, `${x.vrsta === "dobropis" ? "Dobropis" : "Račun"} #${cele(x.id)}`),
        h("span", { class: "znacka " + s[1] }, s[0]),
        h("span", { class: "drobno" }, `naročilo #${cele(x.order_id)}`)),
      h("div", { class: "rc-polja" },
        h("span", {}, h("small", {}, "znesek"), denar(x.znesek_cents)),
        h("span", {}, h("small", {}, "številka"), stevilka),
        h("span", {}, h("small", {}, "ustvarjen"), datum(x.created_at)),
        h("span", {}, h("small", {}, "izdan"), x.izdan_at ? datum(x.izdan_at) : "—"),
        h("span", {}, h("small", {}, "potrjen"), x.potrjen_at ? datum(x.potrjen_at) : "—"),
        h("span", {}, h("small", {}, "poskusov"), cele(x.poskusi))),
      x.zadnja_napaka ? h("div", { class: "rc-napaka" }, x.zadnja_napaka) : null);
  }

  function narisiRacune(d) {
    const koren = $("op_racuni");
    const st = d.stevci || {};
    const izbira = h("select", { id: "op_racun_filter", "aria-label": "Stanje računov", onchange: (ev) => { racunFilter = ev.currentTarget.value; naloziRacune(); } },
      h("option", { value: "" }, "vsa stanja"),
      Object.keys(STANJA_RACUNOV).map((k) => h("option", { value: k }, `${STANJA_RACUNOV[k][0]} (${cele(st[k])})`)));
    izbira.value = racunFilter;
    const items = Array.isArray(d.items) ? d.items : [];
    const telo = [
      h("div", { class: "telo-opomba" }, "Davčno potrjeni računi lastnih dogodkov Outly. Račun v stanju »napaka« zahteva ročni postopek (docs/STATE.md, »Davčno potrjeni računi lastnih dogodkov«); popravek je migracija z Martinovim DA."),
      items.length ? h("div", { class: "rc-seznam" }, items.map(racunKartica)) : h("div", { class: "prazno" }, "Ni računov v tem stanju."),
    ];
    if (items.length >= cele(d.limit)) telo.push(h("div", { class: "telo-opomba" }, `Prikazanih je prvih ${cele(d.limit)} računov (najnovejši prvi); zoži filter.`));
    koren.replaceChildren(h("div", { class: "skupina" },
      h("h2", {}, "Računi", h("span", { class: "desno" }, izbira, h("button", { class: "tih mali", type: "button", onclick: naloziRacune }, "Osveži"))),
      h("div", { class: "telo" }, telo)));
  }

  async function naloziRacune() {
    await varno(async () => {
      const d = await klic("GET", "/admin/api/racuni?limit=100" + (racunFilter ? "&stanje=" + encodeURIComponent(racunFilter) : ""));
      narisiRacune(d);
    });
  }
  async function naloziOpozorila() {
    await varno(async () => {
      opozoriloStanje = await klic("GET", "/admin/api/opozorila");
      narisiOpozorila(opozoriloStanje);
    });
  }
  window.naloziOpozorila = async function () {
    await Promise.all([naloziOpozorila(), naloziRacune()]);
  };
})();
