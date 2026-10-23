// Admin panel, zavihek »Dogodki«: MNOZICNA DEJANJA (#329, nacrt outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md 2.4, I60).
// Kljukice v seznamu dogodkov + vrstica dejanj: Ustavi prodajo / Zazeni prodajo / Med osnutke / Prestavi (samo dogodki brez prodaje). NI mnozicne odpovedi (vracila denarja
// ostanejo posamicna z vpisom ODPOVEJ na strani dogodka). Klic: POST /admin/api/events/bulk { ids (<= 50), dejanje, razlog, zamik_min? }; potrditev prek potrdi() s seznamom
// izbranih naslovov in OBVEZNIM razlogom; po izvedbi rezultat po dogodkih (uspelo / napaka).
// Brez ogrodja in gradnje (DECISIONS 21. 10. 2026). Uporablja globalne funkcije iz index.html in dialog.js: klic, varno, obvesti, h, potrdi.
// XSS: podatki (naslovi dogodkov, sporocila API-ja) v DOM SAMO prek h() / textContent; brez innerHTML in brez inline-atributov (obdelovalniki samo kot funkcije; test_admin_xss.js).
// dogodki.js po vsakem izrisu seznama poklice window.mnozicno.zaSeznam({ vsebnik, dogodki, osvezi }); brez tega modula seznam dela kot prej.
(function () {
  "use strict";
  const NAJVEC = 50;            // skladno s strezniskim IDOV_NAJVEC
  const ZAMIK_NAJVEC_DNI = 30;  // skladno z ZAMIK_NAJVEC_MIN (30 dni)
  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);
  const izbrani = new Map();    // id -> naslov (ostane po osvezitvi seznama; ob vsakem izrisu se skrci na vidne dogodke)
  let trakEl = null, osveziSeznam = null, vidni = [], zasedeno = false, rezultat = null, vsebnikEl = null;

  const DEJANJA = {
    pause: { gumb: "Ustavi prodajo", naslov: "Ustavi prodajo", opis: "Prodaja se ustavi (cena ostane). Čakajoča plačilna okna se prekinejo; že plačane vstopnice ostanejo veljavne.", potrdi: "Ustavi prodajo", nevarno: true },
    resume: { gumb: "Zaženi prodajo", naslov: "Zaženi prodajo", opis: "Prodaja spet teče (če je dogodek objavljen in v oknu prodaje).", potrdi: "Zaženi prodajo", nevarno: false },
    draft: { gumb: "Med osnutke", naslov: "Med osnutke", opis: "Dogodki izginejo iz javnega seznama. Že plačane vstopnice ostanejo veljavne in jih je mogoče skenirati. Odpovedani dogodki se ne spremenijo.", potrdi: "Med osnutke", nevarno: true },
    reschedule: { gumb: "Prestavi", naslov: "Prestavi dogodke", opis: "Premakne začetek, konec in okno prodaje. Samo dogodki BREZ prodanih vstopnic in naročil; ostali se preskočijo (take prestavi posamično).", potrdi: "Prestavi", nevarno: false },
  };
  // Slovenska besedila znanih kod napak (neznana koda: sporočilo API-ja, kot besedilo).
  const NAPAKE = {
    has_sales: "ima prodane vstopnice ali naročila – prestavi posamično",
    event_busy: "dogodek je zaseden, poskusi znova",
    event_cancelled: "dogodek je odpovedan",
    event_finished: "dogodek se je že začel",
    start_in_past: "nov začetek bi bil v preteklosti",
    event_not_found: "dogodka ni več",
    event_changed: "dogodek se je medtem spremenil, poskusi znova",
    not_processed: "ni bil obdelan (zmanjkalo časa), poskusi znova",
    server_error: "napaka strežnika",
  };

  function izbira(id, naslov, vkljuci) {
    if (vkljuci) {
      if (!izbrani.has(id) && izbrani.size >= NAJVEC) { obvesti(`Naenkrat je mogoče izbrati največ ${NAJVEC} dogodkov.`, "slabo"); return false; }
      izbrani.set(id, naslov);
    } else izbrani.delete(id);
    rezultat = null;
    return true;
  }

  function seznamNaslovov() {
    return h("ul", { class: "mn-seznam" }, [...izbrani].map(([id, naslov]) => h("li", {}, h("span", { class: "mono" }, "#" + id), " ", String(naslov))));
  }

  // Zamik za »Prestavi«: dni (lahko decimalno, negativno = nazaj) -> minute; null, ce ni veljaven.
  function zamikIzDni(v) {
    const s = String(v === undefined || v === null ? "" : v).trim().replace(",", ".");
    if (!/^-?\d{1,3}(\.\d{1,3})?$/.test(s)) return null;
    const min = Math.round(Number(s) * 1440);
    return Number.isInteger(min) && min !== 0 && Math.abs(min) <= ZAMIK_NAJVEC_DNI * 1440 ? min : null;
  }

  async function izvedi(dejanje) {
    if (zasedeno || !izbrani.size) return;
    const d = DEJANJA[dejanje];
    const ids = [...izbrani.keys()];
    let zamik = null, zamikVnos = null, razlog = null;
    for (;;) {   // pri »Prestavi« ob neveljavnem premiku okno ostane (vnos se ohrani)
      const vnos = dejanje === "reschedule" ? h("input", { id: "mn_zamik", type: "text", inputmode: "decimal", autocomplete: "off", placeholder: "npr. 7 ali -1" }) : null;
      if (vnos && zamikVnos !== null) vnos.value = zamikVnos;
      const odg = await potrdi({
        naslov: `${d.naslov} (${ids.length})`,
        vsebina: [h("p", {}, d.opis), seznamNaslovov(),
          vnos ? h("div", { class: "dlg-polje" }, h("label", { for: "mn_zamik" }, `Premik v dneh (največ ${ZAMIK_NAJVEC_DNI}; negativno = nazaj; 0,5 = 12 ur)`), vnos) : null],
        potrdiBesedilo: d.potrdi, nevarno: d.nevarno, razlog: "obvezen",
      });
      if (!odg) return;
      if (dejanje === "reschedule") {
        zamikVnos = vnos.value;
        zamik = zamikIzDni(zamikVnos);
        if (zamik === null) { obvesti(`Premik mora biti število dni, ne 0, največ ${ZAMIK_NAJVEC_DNI} naprej ali nazaj.`, "slabo"); continue; }
      }
      razlog = odg.razlog;
      break;
    }
    const telo = { ids, dejanje, razlog };
    if (zamik !== null) telo.zamik_min = zamik;
    zasedeno = true; narisiTrak();
    try {
      await varno(async () => {
        const o = await klic("POST", "/admin/api/events/bulk", telo);
        const rez = Array.isArray(o && o.results) ? o.results : [];
        rezultat = { dejanje, vrstice: ids.map((id) => { const x = rez.find((r) => cele(r.id) === id) || { ok: false, napaka: "not_processed" }; return { id, naslov: izbrani.get(id), ...x }; }) };
        for (const v of rezultat.vrstice) if (v.ok) izbrani.delete(v.id);   // uspeli dogodki iz izbire; neuspeli ostanejo za ponovni poskus
      });
    } finally { zasedeno = false; }
    narisiTrak();
    if (osveziSeznam) osveziSeznam();   // sveze stanje v tabeli; rezultat ostane (zaSeznam ga ponovno narise)
  }

  function opisVrstice(v) {
    if (v.ok) return v.spremenjeno === false ? "brez spremembe (je že tako)" : "uspelo";
    return NAPAKE[v.napaka] || String(v.message || v.napaka || "napaka").slice(0, 200);
  }

  function narisiTrak() {
    if (!trakEl) return;
    const deli = [];
    if (izbrani.size) {
      deli.push(h("div", { class: "mn-vrsta" },
        h("b", {}, `Izbranih: ${izbrani.size}`),
        ["pause", "resume", "draft", "reschedule"].map((k) => { const g = h("button", { type: "button", class: "mali", onclick: () => izvedi(k) }, DEJANJA[k].gumb); g.disabled = zasedeno; return g; }),
        (() => { const g = h("button", { type: "button", class: "tih mali", onclick: () => { izbrani.clear(); rezultat = null; osvezi(); } }, "Počisti izbiro"); g.disabled = zasedeno; return g; })(),
        zasedeno ? h("span", { class: "drobno" }, "Izvajam …") : null));
    }
    if (rezultat) {
      const uspelo = rezultat.vrstice.filter((v) => v.ok).length, napak = rezultat.vrstice.length - uspelo;
      deli.push(h("div", { class: "mn-rezultat", role: "status" },
        h("b", {}, `${DEJANJA[rezultat.dejanje].gumb}: uspelo ${uspelo}, napak ${napak}`),
        h("ul", { class: "mn-seznam" }, rezultat.vrstice.map((v) => h("li", { class: v.ok ? "mn-ok" : "mn-napaka" },
          h("span", { class: "mono" }, "#" + cele(v.id)), " ", String(v.naslov || ""), " – ", h("b", {}, v.ok ? "OK" : "NAPAKA"), ": ", opisVrstice(v))))));
    }
    trakEl.replaceChildren(...deli);
  }

  // Preslika izbiro na kljukice v tabeli (brez ponovnega izrisa tabele).
  function osvezi() {
    for (const [id, polje] of kljukice) polje.checked = izbrani.has(id);
    if (glavna) glavna.checked = vidni.length > 0 && vidni.every((x) => izbrani.has(cele(x.id)));
    narisiTrak();
  }
  const kljukice = new Map();
  let glavna = null;

  function zaSeznam(o) {
    vsebnikEl = o.vsebnik; osveziSeznam = o.osvezi || null; vidni = Array.isArray(o.dogodki) ? o.dogodki : [];
    const vidniId = new Set(vidni.map((x) => cele(x.id)));
    for (const id of [...izbrani.keys()]) if (!vidniId.has(id)) izbrani.delete(id);   // izbira velja za dogodke, ki jih vidis
    for (const x of vidni) if (izbrani.has(cele(x.id))) izbrani.set(cele(x.id), x.title);
    kljukice.clear(); glavna = null;
    trakEl = h("div", { class: "mn-trak", id: "mn_trak" });
    const tabela = Array.from(vsebnikEl.children).find((c) => c.tagName && c.tagName.toLowerCase() === "table");
    if (tabela) {
      const zaustavi = (e) => { if (e && e.stopPropagation) e.stopPropagation(); };
      const glava = Array.from(tabela.children).find((c) => c.tagName.toLowerCase() === "thead");
      const telo = Array.from(tabela.children).find((c) => c.tagName.toLowerCase() === "tbody");
      const glavaVrsta = glava && Array.from(glava.children)[0];
      if (glavaVrsta) {
        glavna = h("input", { type: "checkbox", "aria-label": "Izberi vse prikazane dogodke" });
        glavna.onchange = () => {
          if (glavna.checked) { for (const x of vidni.slice(0, NAJVEC)) izbira(cele(x.id), x.title, true); if (vidni.length > NAJVEC) obvesti(`Izbranih je prvih ${NAJVEC} dogodkov (največ naenkrat).`, "slabo"); }
          else for (const x of vidni) izbira(cele(x.id), x.title, false);
          osvezi();
        };
        glavaVrsta.replaceChildren(h("th", { class: "mn-izbira" }, glavna), ...Array.from(glavaVrsta.children));
      }
      Array.from(telo ? telo.children : []).forEach((tr, i) => {
        const x = vidni[i]; if (!x) return;
        const id = cele(x.id);
        const polje = h("input", { type: "checkbox", "aria-label": "Izberi dogodek " + String(x.title) });
        polje.checked = izbrani.has(id);
        polje.onchange = () => { if (!izbira(id, x.title, polje.checked)) polje.checked = false; osvezi(); };
        const td = h("td", { class: "mn-izbira" }, polje);
        td.onclick = zaustavi; td.onkeydown = zaustavi;   // klik/tipka na kljukici ne odpre urejevalnika (vrstica ima svoj obdelovalnik)
        kljukice.set(id, polje);
        tr.replaceChildren(td, ...Array.from(tr.children));
      });
    }
    vsebnikEl.replaceChildren(trakEl, ...Array.from(vsebnikEl.children));
    osvezi();
  }

  window.mnozicno = { zaSeznam, zamikIzDni, izvedi };
})();
