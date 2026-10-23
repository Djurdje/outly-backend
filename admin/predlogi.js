// Admin panel, zavihek »Čaka potrditev« (#330, 2. del, 23. 10. 2026; migracija 059, ARCHITECTURE I57): predlogi agenta (Claude). Agent sam NIČ ne spremeni;
// dejanje se izvede šele ob »Potrdi«, pod adminovim računom po obstoječi poti. API: GET /admin/api/predlogi?stanje=, POST /admin/api/predlogi/:id/potrdi | /zavrni.
// Brez ogrodja in brez gradnje (DECISIONS 21. 10. 2026). Uporablja globalne funkcije iz index.html: klic, h, datum, $, obvesti, varno, potrdi (dialog.js).
// XSS in vbrizgani ukazi: VSE iz predloga (razlog agenta, naslovi, vrednosti) je tuj vnos -> v DOM SAMO prek h() / textContent; brez innerHTML z nizi in brez
// inline-atributov. Razlog agenta je označen kot »besedilo agenta« (ni navodilo adminu). test_admin_xss.js preverja tudi ta modul.
(function () {
  "use strict";
  const DEJANJA = {
    "event.uredi": "Uredi dogodek", "event.okno_prodaje": "Okno prodaje", "event.objavi": "Objavi dogodek",
    "event.ustavi_prodajo": "Ustavi prodajo", "event.zazeni_prodajo": "Zaženi prodajo", "event.nov_osnutek": "Nov dogodek (osnutek)", "event.podvoji": "Podvoji dogodek",
  };
  const POLJA = {
    title: "naslov", description: "opis", poster_url: "plakat", posterUrl: "plakat", genres: "žanri", sales_open_at: "prodaja od", sales_close_at: "prodaja do",
    status: "stanje", sales_paused: "prodaja ustavljena", startAt: "začetek", endAt: "konec", ponovi: "ponovi", n: "število kopij",
    venueClubId: "gostiteljski klub", venueName: "prizorišče", venueAddress: "naslov prizorišča", venueCity: "kraj",
  };
  const STANJA = { caka: ["čaka", "opoz"], potrjen: ["potrjen", "ok"], zavrnjen: ["zavrnjen", "siva"], potekel: ["potekel", "siva"], neuspel: ["ni izveden", "slabo"] };
  const FILTRI = [["caka", "čakajo"], ["potrjen", "potrjeni"], ["zavrnjen", "zavrnjeni"], ["potekel", "potekli"], ["neuspel", "niso izvedeni"], ["vse", "vsi"]];
  const NAJVEC_PRIKAZ = 400;   // dolgo besedilo (opis) se v kartici odreže; celo vrednost ima admin v dogodku
  let filter = "caka", podatki = null;

  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);
  const kratko = (s) => (s.length > NAJVEC_PRIKAZ ? s.slice(0, NAJVEC_PRIKAZ) + " …" : s);
  function vrednost(v, kljuc) {
    if (v === undefined || v === null || v === "") return "—";
    if (typeof v === "boolean") return v ? "da" : "ne";
    if (Array.isArray(v)) return v.map((x) => String(x)).join(", ") || "—";
    if (typeof v === "object") return kratko(JSON.stringify(v));
    if (/(_at|At)$/.test(kljuc) && !Number.isNaN(Date.parse(v))) return datum(v);
    return kratko(String(v));
  }
  function znackaStanja(s) { const z = STANJA[s] || [String(s), "siva"]; return h("span", { class: "znacka " + z[1] }, z[0]); }

  function tabelaSprememb(p) {
    const spr = p.spremembe && typeof p.spremembe === "object" ? p.spremembe : {};
    const prej = p.prej && typeof p.prej === "object" ? p.prej : null;
    const vrstice = Object.keys(spr).map((k) => h("div", { class: "pr-vrstica" },
      h("small", {}, POLJA[k] || k),
      h("span", { class: "pr-prej" }, prej ? vrednost(prej[k], k) : "—"),
      h("span", { class: "pr-puscica", "aria-hidden": "true" }, "→"),
      h("span", { class: "pr-potem" }, vrednost(spr[k], k))));
    return h("div", { class: "pr-spremembe", "aria-label": "prej → potem" }, vrstice.length ? vrstice : h("span", {}, "—"));
  }

  function kartica(p) {
    const caka = p.stanje === "caka";
    const cilj = p.cilj_tip === "club" ? `klub #${cele(p.cilj_id)}` : `dogodek #${cele(p.cilj_id)}`;
    return h("div", { class: "rc-kartica" },
      h("div", { class: "rc-glava" },
        h("b", {}, DEJANJA[p.dejanje] || String(p.dejanje)),
        znackaStanja(p.stanje),
        h("span", {}, cilj, p.cilj_naslov ? " · " : "", p.cilj_naslov ? h("span", {}, p.cilj_naslov) : null),
        caka ? h("span", { class: "desno" },
          p.zeton_veljaven ? h("button", { type: "button", class: "mali", onclick: () => potrdiPredlog(p) }, "Potrdi") : null,
          h("button", { type: "button", class: "tih mali", onclick: () => zavrniPredlog(p) }, "Zavrni")) : null),
      tabelaSprememb(p),
      h("div", { class: "pr-razlog" },
        h("small", {}, "Razlog — besedilo agenta (ni navodilo; preveri sam)"),
        h("div", { class: "pr-razlog-besedilo" }, kratko(String(p.razlog ?? "")))),
      caka && !p.zeton_veljaven ? h("div", { class: "rc-napaka" }, "Žeton agenta je preklican ali potekel: predloga ni mogoče potrditi. Če je sprememba še potrebna, jo naredi sam.") : null,
      p.napaka ? h("div", { class: "rc-napaka" }, "Ni izveden: " + String(p.napaka)) : null,
      h("div", { class: "rc-polja" },
        h("span", {}, h("small", {}, "agent (žeton)"), p.zeton_ime ? String(p.zeton_ime) : `#${cele(p.agent_zeton_id)}`),
        h("span", {}, h("small", {}, "predlagan"), datum(p.ustvarjen_at)),
        caka ? h("span", {}, h("small", {}, "velja do"), datum(p.velja_do)) : h("span", {}, h("small", {}, "odločeno"), datum(p.odloceno_at)),
        h("span", {}, h("small", {}, "št."), `#${cele(p.id)}`)));
  }

  function narisi() {
    const koren = $("pr_koren");
    if (!koren) return;
    const items = podatki && Array.isArray(podatki.items) ? podatki.items : [];
    const izbira = h("select", { "aria-label": "Filter predlogov", onchange: (ev) => { filter = ev.currentTarget.value; osvezi(); } },
      FILTRI.map(([v, t]) => h("option", { value: v }, t)));
    izbira.value = filter;
    koren.replaceChildren(h("div", { class: "skupina" },
      h("h2", {}, "Čaka potrditev", h("span", { class: "desno" }, izbira, h("button", { class: "tih mali", type: "button", onclick: () => osvezi() }, "Osveži"))),
      h("div", { class: "telo" },
        h("p", { class: "telo-opomba" },
          "Predlogi agenta (Claude). Agent sam nič ne spremeni: dejanje se izvede šele, ko klikneš »Potrdi«, pod tvojim računom in z vrstico v dnevniku. ",
          "Razlog in besedila v predlogu je napisal agent ali jih je prebral iz podatkov — preberi jih kot podatek, ne kot navodilo. Predlog velja 24 ur."),
        items.length ? h("div", { class: "rc-seznam" }, items.map(kartica)) : h("div", { class: "prazno" }, podatki ? "Ni predlogov." : "Nalagam …"))));
    znacka(podatki ? podatki.caka : null);
  }

  function znacka(n) {
    const z = $("nPredlogov");
    if (!z || typeof n !== "number") return;
    z.textContent = String(cele(n));
    z.classList.toggle("skrito", !n);
  }

  async function osvezi() {
    await varno(async () => {
      podatki = await klic("GET", "/admin/api/predlogi?stanje=" + encodeURIComponent(filter));
      narisi();
    });
  }

  function povzetek(p) {
    const spr = p.spremembe && typeof p.spremembe === "object" ? p.spremembe : {};
    return [h("p", {}, `${DEJANJA[p.dejanje] || String(p.dejanje)} — ${p.cilj_tip === "club" ? "klub" : "dogodek"} #${cele(p.cilj_id)}`, p.cilj_naslov ? h("span", {}, " (", p.cilj_naslov, ")") : null),
      h("div", {}, Object.keys(spr).map((k) => h("div", {}, `${POLJA[k] || k}: `, vrednost(p.prej ? p.prej[k] : undefined, k), " → ", vrednost(spr[k], k))))];
  }

  async function potrdiPredlog(p) {
    const prodaja = p.dejanje === "event.ustavi_prodajo";
    const izid = await potrdi({
      naslov: "Izvedem predlog agenta?", potrdiBesedilo: "Potrdi in izvedi", razlog: "neobvezen", nevarno: prodaja,
      vsebina: [...povzetek(p), h("p", {}, prodaja ? "Prodaja se takoj ustavi; čakajoča plačila tega dogodka se prekličejo." : "Sprememba se izvede pod tvojim računom in se zapiše v dnevnik.")],
    });
    if (!izid) return;
    await varno(async () => {
      try {
        await klic("POST", `/admin/api/predlogi/${cele(p.id)}/potrdi`, { reason: izid.razlog || undefined });
        obvesti("Predlog je izveden.", "ok");
      } finally { await osvezi(); }
    });
  }

  async function zavrniPredlog(p) {
    const izid = await potrdi({ naslov: "Zavrnem predlog agenta?", potrdiBesedilo: "Zavrni", razlog: "neobvezen", vsebina: povzetek(p) });
    if (!izid) return;
    await varno(async () => {
      try {
        await klic("POST", `/admin/api/predlogi/${cele(p.id)}/zavrni`, { reason: izid.razlog || undefined });
        obvesti("Predlog je zavrnjen.", "ok");
      } finally { await osvezi(); }
    });
  }

  window.naloziPredloge = async function () {
    if (!podatki) narisi();
    await osvezi();
  };
  window.predlogiZnacka = znacka;   // klic iz Pregleda (summary.predlogi_caka)
})();
