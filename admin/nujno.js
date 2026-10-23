// Admin panel, RDEČ PAS na vrhu (#330, 3. del, 23. 10. 2026; migracija 060, ARCHITECTURE I58): dejanja, ki jih je agent (Claude) izvedel v NUJNEM NAČINU z Martinovo
// pisno potrditvijo (citat iz seje Claude Code). Pas ostane, dokler admin vsakega posebej ne označi z »Pregledal sem« (potrdi() iz dialog.js).
// API: GET /admin/api/predlogi/nujno, POST /admin/api/predlogi/:id/nujno-pregledano. Brez ogrodja in brez gradnje (DECISIONS 21. 10. 2026).
// Uporablja globalne funkcije iz index.html: klic, h, datum, $, obvesti, varno, potrdi. XSS in vbrizgani ukazi: citat, seja, naslovi in vrednosti so tuj vnos
// (citat je napisal agent — streznik ne more preveriti, da je od Martina) -> v DOM SAMO prek h() / textContent; seja NI povezava (samo besedilo). test_admin_xss.js.
(function () {
  "use strict";
  const DEJANJA = {
    "event.uredi": "Uredi dogodek", "event.okno_prodaje": "Okno prodaje", "event.objavi": "Objavi dogodek",
    "event.ustavi_prodajo": "Ustavi prodajo", "event.zazeni_prodajo": "Zaženi prodajo", "event.nov_osnutek": "Nov dogodek (osnutek)", "event.podvoji": "Podvoji dogodek",
  };
  const MAIL = { poslan: "mail poslan", neznan: "mail: izid neznan (preveri Resend)", ni_poslan: "mail NI poslan", caka: "mail se pošilja" };
  const NAJVEC = 300;
  let podatki = null;

  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);
  const kratko = (s) => (s.length > NAJVEC ? s.slice(0, NAJVEC) + " …" : s);
  function vrednost(v) {
    if (v === undefined || v === null || v === "") return "—";
    if (typeof v === "boolean") return v ? "da" : "ne";
    if (typeof v === "object") return kratko(JSON.stringify(v));
    return kratko(String(v));
  }
  function spremembe(p) {
    const spr = p.spremembe && typeof p.spremembe === "object" && !Array.isArray(p.spremembe) ? p.spremembe : {};
    const prej = p.prej && typeof p.prej === "object" && !Array.isArray(p.prej) ? p.prej : {};
    const k = Object.keys(spr);
    return k.length ? k.map((x) => h("div", {}, `${x}: `, vrednost(prej[x]), " → ", vrednost(spr[x]))) : [h("div", {}, "—")];
  }

  function postavka(p) {
    const cilj = `${p.cilj_tip === "club" ? "klub" : "dogodek"} #${cele(p.cilj_id)}`;
    return h("div", { class: "nj-postavka" },
      h("div", { class: "nj-glava" },
        h("b", {}, DEJANJA[p.dejanje] || String(p.dejanje)),
        h("span", {}, cilj, p.cilj_naslov ? " · " : "", p.cilj_naslov ? h("span", {}, String(p.cilj_naslov)) : null),
        h("span", {}, datum(p.nujno_at)),
        h("span", { class: "desno" }, p.nujno_pregledano_at ? h("span", { class: "znacka siva" }, "pregledano")
          : h("button", { type: "button", class: "mali", onclick: () => pregledal(p) }, "Pregledal sem"))),
      h("div", { class: "nj-spremembe" }, spremembe(p)),
      h("div", { class: "nj-citat" },
        h("small", {}, "Potrditev, ki jo je agent navedel kot tvojo (citat) — preveri, ali si jo res napisal ti"),
        h("div", { class: "nj-citat-besedilo" }, "«", String(p.nujno_potrditev ?? ""), "»")),
      h("div", { class: "nj-polja" },
        h("span", {}, h("small", {}, "seja"), h("span", { class: "nj-seja" }, String(p.nujno_seja ?? ""))),
        h("span", {}, h("small", {}, "žeton"), p.zeton_ime ? String(p.zeton_ime) : `#${cele(p.agent_zeton_id)}`),
        h("span", {}, h("small", {}, "mail"), MAIL[p.mail] || String(p.mail ?? "")),
        h("span", {}, h("small", {}, "predlog"), `#${cele(p.id)}`)));
  }

  function narisi() {
    const koren = $("nujno_pas");
    if (!koren) return;
    const items = podatki && Array.isArray(podatki.items) ? podatki.items : [];
    if (!items.length) { koren.replaceChildren(); koren.classList.add("skrito"); return; }
    koren.classList.remove("skrito");
    koren.replaceChildren(h("div", { class: "nj-pas", role: "alert" },
      h("div", { class: "nj-naslov" },
        h("b", {}, `Agent je v nujnem načinu izvedel ${cele(podatki.nepregledanih)} ${cele(podatki.nepregledanih) === 1 ? "dejanje" : "dejanj"} brez tvojega klika`),
        h("span", {}, ` · zadnjih 24 h: ${cele(podatki.zadnjih_24h)} od ${cele(podatki.meja_24h)}`)),
      h("p", { class: "nj-opomba" },
        "Vsako je izvedel s sklicem na tvojo pisno potrditev v seji Claude Code. Če katere nisi napisal ti: v zavihku Agent takoj prekliči žeton in dejanje popravi. ",
        "Pas ostane, dokler vsakega ne označiš z »Pregledal sem«."),
      h("div", { class: "nj-seznam" }, items.map(postavka))));
  }

  async function osvezi() {
    await varno(async () => {
      podatki = await klic("GET", "/admin/api/predlogi/nujno");
      narisi();
    });
  }

  async function pregledal(p) {
    const izid = await potrdi({
      naslov: "Pregledal sem nujno dejanje?", potrdiBesedilo: "Pregledal sem", razlog: "neobvezen",
      vsebina: [h("p", {}, `${DEJANJA[p.dejanje] || String(p.dejanje)} — ${p.cilj_tip === "club" ? "klub" : "dogodek"} #${cele(p.cilj_id)}`),
        h("div", {}, spremembe(p)),
        h("p", {}, "Citat: «", String(p.nujno_potrditev ?? ""), "»"),
        h("p", {}, "Potrdi samo, če si to potrditev res napisal ti. Če je nisi, zapri to okno in prekliči žeton v zavihku Agent.")],
    });
    if (!izid) return;
    await varno(async () => {
      try {
        await klic("POST", `/admin/api/predlogi/${cele(p.id)}/nujno-pregledano`, { reason: izid.razlog || undefined });
        obvesti("Označeno kot pregledano.", "ok");
      } finally { await osvezi(); }
    });
  }

  window.naloziNujnoPas = osvezi;   // klic ob prikazu panela in ob osvežitvi Pregleda (index.html)
})();
