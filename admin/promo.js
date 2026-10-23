// Admin panel, zavihek »Promo kode« (065, I61; Martin 23. 10. 2026): SAMO STATISTIKA. Koda, ki jo kupec vpise ob nakupu navadne vstopnice, ne spremeni cene, popusta ali
// provizije; panel samo steje, koliko vstopnic je bilo prodanih pri katerem dogodku s posamezno kodo. Seznam kod z vsoto kart, obrazec za novo kodo (koda, ime/opis,
// KLUB = vsi dogodki kluba ALI izbrani dogodki), vklop/izklop, klik na »Statistika« = tabela po dogodkih (dogodek, datum, klub, karte, narocila, bruto), »Uredi« = ime in obseg.
// API (index.js): GET/POST /admin/api/promo-codes, PATCH /admin/api/promo-codes/:id, GET /admin/api/promo-codes/:id/stats; klubi in dogodki iz obstojecih GET /admin/api/clubs in /events.
// Brez ogrodja in brez gradnje (DECISIONS 21. 10. 2026). Uporablja globalne funkcije iz index.html: klic, h, datum, evriCelo, obvesti, varno, potrdi (dialog.js).
// XSS: podatki v DOM SAMO prek h() / textContent; brez innerHTML in brez inline-atributov (test_admin_xss.js preverja tudi ta modul).
(function () {
  "use strict";
  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);
  const KODA_VNOS = /^[A-Za-z0-9_-]{3,32}$/;

  let kode = null;                 // seznam iz API-ja (null = se ni nalozen)
  let klubi = null, dogodki = null; // izbira obsega: nalozeno ob prvi uporabi obrazca
  let odprta = null;               // { id, stats } | { id, uredi: true }
  const forma = { koda: "", oznaka: "", nacin: "klub", klub: "", dogodki: new Set(), filter: "" };
  let urejanje = null;             // { oznaka, klub, dogodki:Set, filter } za odprto kodo

  const besedilo = (v) => String(v === null || v === undefined ? "" : v);
  function obseg(k) {
    const deli = [];
    if (k.club) deli.push(`vsi dogodki kluba ${besedilo(k.club.name)}`);
    const ev = Array.isArray(k.events) ? k.events : [];
    if (ev.length) deli.push(ev.length === 1 ? `dogodek ${besedilo(ev[0].title)}` : `${ev.length} dogodkov`);
    return deli.join(" + ") || "—";
  }

  async function naloziIzbire() {
    if (klubi && dogodki) return;
    const [k, d] = await Promise.all([klic("GET", "/admin/api/clubs"), klic("GET", "/admin/api/events")]);
    klubi = (Array.isArray(k) ? k : []).map((x) => ({ id: cele(x.id), name: besedilo(x.name), city: besedilo(x.city) })).sort((a, b) => a.name.localeCompare(b.name));
    dogodki = (Array.isArray(d) ? d : []).filter((x) => x.status !== "cancelled")
      .map((x) => ({ id: cele(x.id), title: besedilo(x.title), club: besedilo(x.club_name), start_at: x.start_at }));
  }

  // Izbira obsega: klub (select) in/ali dogodki (kljukice s filtrom). `st` = objekt s poljema klub (niz) in dogodki (Set) ter filter; spremembe pisejo vanj.
  function izbiraObsega(st, dovoliBrezKluba, osvezi) {
    const klubIzbira = h("select", { "aria-label": "Klub", onchange: (ev) => { st.klub = ev.currentTarget.value; } },
      h("option", { value: "" }, dovoliBrezKluba ? "— brez kluba —" : "— izberi klub —"),
      (klubi || []).map((x) => h("option", { value: String(x.id) }, x.city ? `${x.name} (${x.city})` : x.name)));
    klubIzbira.value = st.klub;
    const iskano = st.filter.trim().toLowerCase();
    const vidni = (dogodki || []).filter((x) => st.dogodki.has(x.id) || !iskano || `${x.club} ${x.title}`.toLowerCase().includes(iskano)).slice(0, 80);
    const seznam = h("div", { class: "pk-dogodki", role: "group", "aria-label": "Dogodki" }, vidni.map((x) => {
      const polje = h("input", { type: "checkbox", "aria-label": x.title });
      polje.checked = st.dogodki.has(x.id);
      polje.onchange = () => { if (polje.checked) st.dogodki.add(x.id); else st.dogodki.delete(x.id); osvezi(); };
      return h("label", { class: "pk-dogodek" }, polje, h("span", {}, `${x.club} · ${x.title} · ${datum(x.start_at)}`));
    }));
    const filter = h("input", { type: "text", placeholder: "Išči dogodek ali klub", maxlength: "60", autocomplete: "off", "aria-label": "Išči dogodek", oninput: (ev) => { st.filter = ev.currentTarget.value; } });
    filter.value = st.filter;
    filter.onchange = osvezi;
    return { klubIzbira, filter, seznam, izbranih: st.dogodki.size };
  }

  function obrazecNova() {
    const f = forma;
    const koda = h("input", { type: "text", maxlength: "32", placeholder: "npr. max12", autocomplete: "off", autocapitalize: "characters", spellcheck: "false", "aria-label": "Koda",
      oninput: (ev) => { f.koda = ev.currentTarget.value; } });
    koda.value = f.koda;
    const oznaka = h("input", { type: "text", maxlength: "80", placeholder: "npr. Max (lastnik kode)", autocomplete: "off", "aria-label": "Ime ali opis lastnika kode",
      oninput: (ev) => { f.oznaka = ev.currentTarget.value; } });
    oznaka.value = f.oznaka;
    const st = { get klub() { return f.klub; }, set klub(v) { f.klub = v; }, dogodki: f.dogodki, get filter() { return f.filter; }, set filter(v) { f.filter = v; } };
    const iz = izbiraObsega(st, false, narisi);
    // Dva nacina, eden naenkrat: klub ali dogodki (API sprejme tudi oboje, panel to namenoma ne ponuja).
    const nacin = h("select", { "aria-label": "Za kaj velja koda", onchange: (ev) => { f.nacin = ev.currentTarget.value === "dogodki" ? "dogodki" : "klub"; narisi(); } },
      h("option", { value: "klub" }, "Vsi dogodki enega kluba"), h("option", { value: "dogodki" }, "Samo izbrani dogodki"));
    nacin.value = f.nacin;
    return h("div", { class: "pk-obrazec" },
      h("label", {}, h("small", {}, "koda (kupec jo vpiše ob nakupu)"), koda),
      h("label", {}, h("small", {}, "ime / opis"), oznaka),
      h("label", {}, h("small", {}, "velja za"), nacin),
      f.nacin === "klub" ? h("label", {}, h("small", {}, "klub"), iz.klubIzbira)
        : h("div", { class: "pk-izbira" }, h("small", {}, `dogodki (izbranih: ${iz.izbranih})`), iz.filter, iz.seznam),
      h("div", { class: "pk-gumbi" }, h("button", { type: "button", onclick: ustvari }, "Ustvari kodo")));
  }

  async function ustvari() {
    const f = forma;
    const koda = f.koda.trim();
    if (!KODA_VNOS.test(koda)) { obvesti("Koda: 3–32 znakov (črke, številke, - in _).", "slabo"); return; }
    if (!f.oznaka.trim()) { obvesti("Vpiši ime ali opis lastnika kode.", "slabo"); return; }
    const telo = { code: koda, label: f.oznaka.trim() };
    if (f.nacin === "klub") {
      if (!f.klub) { obvesti("Izberi klub.", "slabo"); return; }
      telo.club_id = cele(f.klub);
    } else {
      if (!f.dogodki.size) { obvesti("Izberi vsaj en dogodek.", "slabo"); return; }
      telo.event_ids = [...f.dogodki];
    }
    await varno(async () => {
      let nova;
      try { nova = await klic("POST", "/admin/api/promo-codes", telo); }
      catch (e) {
        if (/promo_code_exists|already exists/.test(besedilo(e.message))) { obvesti("Koda s tem besedilom že obstaja.", "slabo"); return; }
        throw e;
      }
      obvesti(`Koda ${besedilo(nova.code)} je ustvarjena.`, "ok");
      forma.koda = ""; forma.oznaka = ""; forma.dogodki = new Set(); forma.filter = "";
      await osvezi();
    });
  }

  async function preklopi(k) {
    const vklop = !k.active;
    const izid = await potrdi({
      naslov: vklop ? "Vklopim kodo?" : "Izklopim kodo?", potrdiBesedilo: vklop ? "Vklopi" : "Izklopi", nevarno: !vklop, razlog: "neobvezen",
      vsebina: [h("p", {}, vklop ? `Koda ${besedilo(k.code)} bo spet sprejeta ob nakupu vstopnic.`
        : `Koda ${besedilo(k.code)} ne bo več sprejeta (kupec dobi sporočilo, da koda ne velja). Že prodane vstopnice ostanejo v statistiki.`)],
    });
    if (!izid) return;
    await varno(async () => {
      await klic("PATCH", `/admin/api/promo-codes/${cele(k.id)}`, izid.razlog ? { active: vklop, reason: izid.razlog } : { active: vklop });
      obvesti(vklop ? "Koda je vklopljena." : "Koda je izklopljena.", "ok");
      await osvezi();
    });
  }

  async function pokaziStatistiko(k) {
    if (odprta && odprta.id === k.id && odprta.stats) { odprta = null; narisi(); return; }
    await varno(async () => {
      const s = await klic("GET", `/admin/api/promo-codes/${cele(k.id)}/stats`);
      odprta = { id: k.id, stats: s };
      narisi();
    });
  }

  async function odpriUrejanje(k) {
    if (odprta && odprta.id === k.id && odprta.uredi) { odprta = null; narisi(); return; }
    await varno(async () => {
      await naloziIzbire();
      urejanje = { oznaka: besedilo(k.label), klub: k.club ? String(cele(k.club.id)) : "", dogodki: new Set((k.events || []).map((e) => cele(e.id))), filter: "" };
      odprta = { id: k.id, uredi: true };
      narisi();
    });
  }

  async function shrani(k) {
    const u = urejanje;
    if (!u.oznaka.trim()) { obvesti("Ime ali opis ne sme biti prazen.", "slabo"); return; }
    if (!u.klub && !u.dogodki.size) { obvesti("Koda mora veljati za klub ali vsaj en dogodek.", "slabo"); return; }
    await varno(async () => {
      await klic("PATCH", `/admin/api/promo-codes/${cele(k.id)}`, { label: u.oznaka.trim(), club_id: u.klub ? cele(u.klub) : null, event_ids: [...u.dogodki] });
      obvesti("Koda je shranjena.", "ok");
      odprta = null;
      await osvezi();
    });
  }

  function podrobnosti(k) {
    if (!odprta || odprta.id !== k.id) return null;
    if (odprta.uredi) {
      const u = urejanje;
      const oznaka = h("input", { type: "text", maxlength: "80", autocomplete: "off", "aria-label": "Ime ali opis", oninput: (ev) => { u.oznaka = ev.currentTarget.value; } });
      oznaka.value = u.oznaka;
      const iz = izbiraObsega(u, true, narisi);
      return h("div", { class: "pk-podrobnosti" },
        h("p", { class: "telo-opomba" }, `Besedila kode ${besedilo(k.code)} ni mogoče spremeniti. Obseg: klub (vsi njegovi dogodki) in/ali izbrani dogodki.`),
        h("div", { class: "pk-obrazec" },
          h("label", {}, h("small", {}, "ime / opis"), oznaka),
          h("label", {}, h("small", {}, "klub"), iz.klubIzbira),
          h("div", { class: "pk-izbira" }, h("small", {}, `dogodki (izbranih: ${iz.izbranih})`), iz.filter, iz.seznam),
          h("div", { class: "pk-gumbi" }, h("button", { type: "button", onclick: () => shrani(k) }, "Shrani"), h("button", { type: "button", class: "tih", onclick: () => { odprta = null; narisi(); } }, "Zapri"))));
    }
    const s = odprta.stats, ev = Array.isArray(s.events) ? s.events : [], t = s.total || {};
    const testno = cele(t.test_orders) > 0;
    const vrstica = (x) => h("tr", {},
      h("td", {}, besedilo(x.title)), h("td", {}, datum(x.start_at)), h("td", {}, besedilo(x.club_name)),
      h("td", { class: "pk-st" }, String(cele(x.tickets_sold))), h("td", { class: "pk-st" }, String(cele(x.orders))), h("td", { class: "pk-st" }, evriCelo(cele(x.gross_cents))));
    return h("div", { class: "pk-podrobnosti" },
      ev.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Dogodek", "Datum", "Klub", "Karte", "Naročila", "Bruto"].map((g) => h("th", {}, g)))),
        h("tbody", {}, ev.map(vrstica),
          h("tr", { class: "pk-skupaj" }, h("td", {}, "Skupaj"), h("td", {}), h("td", {}),
            h("td", { class: "pk-st" }, String(cele(t.tickets_sold))), h("td", { class: "pk-st" }, String(cele(t.orders))), h("td", { class: "pk-st" }, evriCelo(cele(t.gross_cents))))))
        : h("div", { class: "prazno" }, "Ni dogodkov ali prodaje s to kodo."),
      h("p", { class: "telo-opomba" }, "Šteje samo plačana naročila navadnih vstopnic; v celoti vrnjena naročila v kartah ne štejejo (kot v Financah). Brez popusta: koda ne spremeni cene."),
      testno ? h("p", { class: "telo-opomba" }, `Poleg tega testni nakupi (lazni način, Stripe sandbox): ${cele(t.test_tickets_sold)} kart v ${cele(t.test_orders)} naročilih (niso v zgornjih številkah).`) : null);
  }

  function vrsticaKode(k) {
    return h("div", { class: "rc-kartica" + (k.active ? "" : " pk-izklopljena") },
      h("div", { class: "rc-glava" },
        h("b", { class: "mono" }, besedilo(k.code)),
        h("span", {}, besedilo(k.label)),
        h("span", { class: "znacka " + (k.active ? "ok" : "siva") }, k.active ? "aktivna" : "izklopljena"),
        h("span", { class: "desno" },
          h("button", { type: "button", class: "tih mali", onclick: () => pokaziStatistiko(k) }, "Statistika"),
          h("button", { type: "button", class: "tih mali", onclick: () => odpriUrejanje(k) }, "Uredi"),
          h("button", { type: "button", class: (k.active ? "nevarno" : "dobro") + " mali", onclick: () => preklopi(k) }, k.active ? "Izklopi" : "Vklopi"))),
      h("div", { class: "rc-polja" },
        h("span", {}, h("small", {}, "velja za"), obseg(k)),
        h("span", {}, h("small", {}, "prodanih kart"), String(cele(k.tickets_sold))),
        h("span", {}, h("small", {}, "naročil"), String(cele(k.orders))),
        h("span", {}, h("small", {}, "bruto"), evriCelo(cele(k.gross_cents))),
        h("span", {}, h("small", {}, "ustvarjena"), datum(k.created_at))),
      podrobnosti(k));
  }

  function narisi() {
    const koren = document.getElementById("pk_koren");
    if (!koren) return;
    const seznam = Array.isArray(kode) ? kode : [];
    const skupajKart = seznam.reduce((s, k) => s + cele(k.tickets_sold), 0);
    koren.replaceChildren(h("div", { class: "skupina" },
      h("h2", {}, "Promo kode", h("span", { class: "desno" }, h("button", { class: "tih mali", type: "button", onclick: () => window.naloziPromo() }, "Osveži"))),
      h("div", { class: "telo" },
        h("p", { class: "telo-opomba" }, "Samo statistika: kupec kodo (npr. MAX12) vpiše ob nakupu navadne vstopnice, a ne dobi popusta in cena se ne spremeni. Tu vidiš, koliko kart je bilo prodanih pri katerem dogodku s posamezno kodo. VIP mize kod ne sprejemajo."),
        obrazecNova(),
        seznam.length ? h("p", { class: "telo-opomba" }, `Skupaj prodanih kart prek kod: ${skupajKart}`) : null,
        seznam.length ? h("div", { class: "rc-seznam" }, seznam.map(vrsticaKode)) : h("div", { class: "prazno" }, kode ? "Še ni promo kod." : "Nalagam …"))));
  }

  async function osvezi() {
    await varno(async () => {
      await naloziIzbire();
      kode = await klic("GET", "/admin/api/promo-codes");
      // odprta statistika se osvezi skupaj s seznamom (po vklopu/izklopu), urejanje ostane kot je
      if (odprta && odprta.stats && kode.some((k) => k.id === odprta.id)) odprta = { id: odprta.id, stats: await klic("GET", `/admin/api/promo-codes/${cele(odprta.id)}/stats`) };
      else if (odprta && !odprta.uredi) odprta = null;
      narisi();
    });
  }

  window.naloziPromo = async function () {
    if (!kode) narisi();
    await osvezi();
  };
})();
