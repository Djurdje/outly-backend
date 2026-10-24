// Admin panel, nadzorna plosca »Danes« na vrhu zavihka Pregled (#326, 23. 10. 2026): prodaja danes / 7 dni, racuni, nocojsnji dogodki z vstopi,
// rdeca opozorila. Podatke da GET /admin/api/danes (admin_nadzor.js; strezniski predpomnilnik 10 s, READ ONLY, nikoli skenPool).
// Osvezevanje vsakih 20 s SAMO, ko je zavihek brskalnika viden IN je odprt zavihek Pregled; ob 503 (strezniku je rok potekel) premor 60 s in napis »podatki zastareli«.
// Brez ogrodja in brez gradnje (DECISIONS 21. 10. 2026). Uporablja globalne funkcije iz index.html: klic, h, datum, $, obvesti, pokaziZavihek.
// XSS: podatki v DOM SAMO prek h() / textContent; brez innerHTML z nizi in brez inline-atributov (onclick-nizov) (test_admin_xss.js preverja tudi ta modul).
(function () {
  "use strict";
  const OSVEZI_MS = 20000, PREMOR_503_MS = 60000, NAJMANJ_MED_KLICI_MS = 3000, ROK_KLICA_MS = 15000;
  let podatki = null, zastarelo = false, sporocilo = "", zadnjiUspeh = 0, pavzaDo = 0, vTeku = false, casovnik = null;

  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);
  // Celi centi -> "1.234,50 €" brez deljenja s plavajoco vejico (I9).
  function denar(c) {
    const x = cele(c), evri = String(Math.floor(x / 100)).replace(/\B(?=(\d{3})+(?!\d))/g, ".");
    return evri + "," + String(x % 100).padStart(2, "0") + " €";
  }
  const PRODAJA = { tece: ["prodaja teče", "ok"], ustavljena: ["prodaja ustavljena", "slabo"], razprodano: ["razprodano", "siva"], zaprta: ["prodaja zaprta", "siva"] };

  function vidno() {
    const panel = $("panel"), pregled = $("z-pregled");
    return document.visibilityState === "visible" && !!panel && !panel.classList.contains("skrito") && !!pregled && !pregled.classList.contains("skrito");
  }

  function naDogodek(id) {
    if (!Number.isSafeInteger(id) || id <= 0) return;
    history.pushState(null, "", "#/dogodki/" + id);
    pokaziZavihek("dogodki");
  }

  function kartica(vrednost, ime, pod, razred) {
    return h("div", { class: "stevilka" + (razred ? " " + razred : "") }, h("b", {}, vrednost), h("span", {}, ime), pod ? h("small", {}, pod) : null);
  }
  function prodajaKartica(p, ime, razred) {
    const n = cele(p && p.narocila), v = cele(p && p.vstopnice);
    return kartica(denar(p && p.bruto_cents), ime, `${n} ${n === 1 ? "naročilo" : "naročil"} · ${v} ${v === 1 ? "vstopnica" : "vstopnic"}`, razred);
  }

  function nocojVrstica(e) {
    const id = cele(e.id);
    const p = PRODAJA[e.prodaja] || [String(e.prodaja || "?"), "siva"];
    const kap = e.kapaciteta === null || e.kapaciteta === undefined ? "" : " / " + cele(e.kapaciteta);
    return h("a", { class: "dn-nocoj", href: "#/dogodki/" + id, onclick: (ev) => { ev.preventDefault(); naDogodek(id); } },
      h("span", { class: "dn-nocoj-glava" }, h("b", {}, e.naslov), h("span", { class: "znacka " + p[1] }, p[0])),
      h("span", { class: "dn-nocoj-pod" }, `${e.klub} · ${datum(e.start_at)}`),
      h("span", { class: "dn-nocoj-stevila" },
        h("span", {}, h("b", {}, cele(e.vstopi)), " vstopilo"),
        h("span", {}, h("b", {}, cele(e.vstopi_15min)), " v zadnjih 15 min"),
        h("span", {}, h("b", {}, cele(e.prodano) + kap), " prodano")));
  }

  function narisi() {
    const koren = $("dn_koren");
    if (!koren) return;
    const d = podatki;
    const stanje = h("span", { class: "desno" },
      zastarelo ? h("span", { class: "znacka opoz", role: "status" }, "podatki zastareli") : null,
      zadnjiUspeh ? h("span", { class: "dn-cas" }, "osveženo " + new Date(zadnjiUspeh).toLocaleTimeString("sl-SI", { hour: "2-digit", minute: "2-digit", second: "2-digit" })) : null,
      h("button", { class: "tih mali", type: "button", onclick: () => osvezi(true) }, "Osveži"));
    const glava = h("h2", {}, "Danes", stanje);
    const telo = [];
    if (sporocilo) telo.push(h("div", { class: "opozorilo", role: "alert" }, sporocilo));
    if (!d) {
      telo.push(h("div", { class: "prazno" }, zastarelo ? "Podatkov ni mogoče naložiti." : "Nalagam …"));
    } else {
      const rdeca = d.opozorila_rdeca;
      const imaRdeca = typeof rdeca === "number";
      telo.push(h("div", { class: "stevilke dn-kartice" },
        prodajaKartica(d.prodaja && d.prodaja.danes, "prodaja danes"),
        prodajaKartica(d.prodaja && d.prodaja.dni7, "zadnjih 7 dni"),
        kartica(cele(d.racuni && d.racuni.izdani_danes), "računov izdanih danes", `čaka ${cele(d.racuni && d.racuni.caka)} · napaka ${cele(d.racuni && d.racuni.napaka)}`,
          cele(d.racuni && d.racuni.napaka) > 0 ? "pozor" : (cele(d.racuni && d.racuni.caka) > 0 ? "opoz" : "")),
        h("button", { class: "stevilka dn-klik " + (imaRdeca && rdeca > 0 ? "pozor" : ""), type: "button", onclick: () => pokaziZavihek("opozorila") },
          h("b", {}, imaRdeca ? rdeca : "—"), h("span", {}, "rdečih opozoril"), h("small", {}, "odpri seznam opozoril"))));
      const nocoj = Array.isArray(d.nocoj) ? d.nocoj : [];
      telo.push(h("h3", { class: "dn-podnaslov" }, "Nocoj"));
      telo.push(nocoj.length ? h("div", { class: "dn-nocoj-seznam" }, nocoj.map(nocojVrstica)) : h("div", { class: "prazno" }, "Nocoj ni objavljenih dogodkov."));
      if (imaRdeca) {
        const znacka = $("nOpozorila");
        if (znacka) { znacka.textContent = rdeca; znacka.classList.toggle("skrito", !rdeca); }
      }
    }
    koren.replaceChildren(h("div", { class: "skupina" }, glava, h("div", { class: "telo" }, telo)));
  }

  function planiraj(ms) { clearTimeout(casovnik); casovnik = setTimeout(tik, ms); }
  function tik() {
    if (!vidno()) { planiraj(OSVEZI_MS); return; }   // zavihek brskalnika ali panela ni viden: ne klici streznika
    osvezi(false);
  }
  // Rok klica: brez njega obvisel zahtevek (polodprta povezava, strezniku nic ne odgovori) drzi vTeku=true za vedno in osvezevanje se tiho ustavi.
  // Ob izteku fetch zavrze AbortSignal (TimeoutError), finally spodaj ponastavi vTeku, narisi() pokaze »podatki zastareli«, casovnik tece naprej.
  function rokKlica() {
    if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") return AbortSignal.timeout(ROK_KLICA_MS);
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), ROK_KLICA_MS);
    return ctrl.signal;
  }
  async function osvezi(sila) {
    if (vTeku) return;
    if (!sila && Date.now() < pavzaDo) { planiraj(pavzaDo - Date.now() + 50); return; }   // veriga osvezevanja se ne sme ugasniti
    vTeku = true;
    let naslednji = OSVEZI_MS;
    try {
      podatki = await klic("GET", "/admin/api/danes", undefined, true, rokKlica());
      zastarelo = false; sporocilo = ""; zadnjiUspeh = Date.now(); pavzaDo = 0;
    } catch (e) {
      zastarelo = true;
      if (e && e.status === 503) { naslednji = PREMOR_503_MS; pavzaDo = Date.now() + PREMOR_503_MS; sporocilo = "Strežnik je zaseden: nadzorna plošča se ne osvežuje 60 s. Prikazani so zadnji znani podatki."; }
      else if (e && (e.name === "TimeoutError" || e.name === "AbortError")) sporocilo = "Strežnik ni odgovoril v " + (ROK_KLICA_MS / 1000) + " s. Prikazani so zadnji znani podatki.";
      else sporocilo = "Osveževanje ni uspelo: " + ((e && e.message) || "napaka");
    } finally {
      vTeku = false;
      narisi();
      planiraj(naslednji);
    }
  }

  // Klic iz naloziPregled() (ob odprtju zavihka Pregled in po dejanjih): ne pogosteje kot na 3 s, razen ob izrecnem »Osveži«.
  window.danesOsvezi = function (sila) {
    if (!vidno()) return Promise.resolve();
    if (!podatki) narisi();
    if (sila || Date.now() - zadnjiUspeh > NAJMANJ_MED_KLICI_MS) return osvezi(!!sila);
    return Promise.resolve();
  };
  document.addEventListener("visibilitychange", () => { if (vidno() && Date.now() - zadnjiUspeh > OSVEZI_MS) osvezi(false); });
  planiraj(OSVEZI_MS);
})();
