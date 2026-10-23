// Admin panel, zavihek »Agent« (#330, 23. 10. 2026): zetoni za agenta (Claude); obseg `beri` ali `beri + predlagaj` (2. del, 059: predlogi, ki jih admin potrdi v »Čaka potrditev«). Seznam (ime, obseg, velja do, zadnja raba, stanje), »Ustvari zeton«
// (potrdi() z obveznim razlogom; zeton se prikaze ENKRAT z gumbom »Kopiraj«) in »Preklici« (potrdi()). API: GET/POST /admin/api/agent-zetoni, POST .../:id/preklici (agent_api.js).
// Zeton v cistopisu je samo v spremenljivki `prikazanZeton`, dokler ga admin ne zapre ali ne osvezi zavihka; nikamor se ne shrani (ne localStorage, ne URL).
// Brez ogrodja in brez gradnje (DECISIONS 21. 10. 2026). Uporablja globalne funkcije iz index.html: klic, h, datum, $, obvesti, varno, potrdi (dialog.js).
// XSS: podatki v DOM SAMO prek h() / textContent; brez innerHTML z nizi in brez inline-atributov (onclick-nizov) (test_admin_xss.js preverja tudi ta modul).
(function () {
  "use strict";
  const STANJA = { aktiven: ["aktiven", "ok"], potekel: ["potekel", "siva"], preklican: ["preklican", "siva"] };
  const DNEVI = [[7, "7 dni"], [30, "30 dni (privzeto)"], [90, "90 dni (najvec)"]];
  const GOSTITELJ = "outly-backend-roy3.onrender.com";
  const OBSEGI = [["beri", "samo branje"], ["beri+predlagaj", "branje + predlogi (potrdiš jih ti)"]];
  let podatki = null, prikazanZeton = null, formIme = "Claude Code", formDni = 30, formObseg = "beri";

  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);

  async function kopiraj(polje) {
    try {
      await navigator.clipboard.writeText(prikazanZeton.zeton);
      obvesti("Žeton je kopiran.", "ok");
    } catch (_) {
      polje.focus(); polje.select();
      obvesti("Kopiranje ni uspelo; žeton je označen, pritisni Ctrl+C.", "opoz");
    }
  }

  function okvirZetona() {
    if (!prikazanZeton) return null;
    const polje = h("input", { type: "text", readonly: "", class: "ag-zeton", value: prikazanZeton.zeton, "aria-label": "Žeton agenta", spellcheck: "false", autocomplete: "off" });
    return h("div", { class: "ag-nov", role: "status" },
      h("b", {}, `Žeton »${prikazanZeton.ime}« je ustvarjen. Prikazan je samo zdaj.`),
      h("div", { class: "ag-vrstica" }, polje, h("button", { type: "button", onclick: () => kopiraj(polje) }, "Kopiraj")),
      h("p", {}, `Vpiši ga v nastavitve okolja Claude Code (Network secrets) za gostitelja ${GOSTITELJ} — ne v chat in ne v repozitorij. Ko zapreš ta okvir ali osvežiš zavihek, žetona ni mogoče več videti; če ga izgubiš, ustvari novega in prekliči starega.`),
      h("div", { class: "ag-vrstica" }, h("button", { type: "button", class: "tih", onclick: () => { prikazanZeton = null; narisi(); } }, "Zapri (žetona ne bom več videl)")));
  }

  function kartica(z) {
    const s = STANJA[z.stanje] || [String(z.stanje), "siva"];
    const obseg = Array.isArray(z.obseg) ? z.obseg.join(", ") : "";
    return h("div", { class: "rc-kartica" },
      h("div", { class: "rc-glava" },
        h("b", {}, z.ime),
        h("span", { class: "znacka " + s[1] }, s[0]),
        z.stanje === "aktiven" ? h("span", { class: "desno" }, h("button", { type: "button", class: "nevarno mali", onclick: () => preklici(z) }, "Prekliči")) : null),
      h("div", { class: "rc-polja" },
        h("span", {}, h("small", {}, "obseg"), obseg || "—"),
        h("span", {}, h("small", {}, "velja do"), datum(z.velja_do)),
        h("span", {}, h("small", {}, "zadnja raba"), z.zadnja_raba_at ? datum(z.zadnja_raba_at) : "še nikoli"),
        h("span", {}, h("small", {}, "ustvarjen"), datum(z.created_at)),
        z.preklican_at ? h("span", {}, h("small", {}, "preklican"), datum(z.preklican_at)) : null,
        h("span", {}, h("small", {}, "št."), `#${cele(z.id)}`)));
  }

  function narisi() {
    const koren = $("ag_koren");
    if (!koren) return;
    const items = podatki && Array.isArray(podatki.items) ? podatki.items : [];
    const imePolje = h("input", { id: "ag_ime", type: "text", maxlength: "60", value: formIme, autocomplete: "off", "aria-label": "Ime žetona", oninput: (ev) => { formIme = ev.currentTarget.value; } });
    const dniIzbira = h("select", { id: "ag_dni", "aria-label": "Veljavnost žetona", onchange: (ev) => { formDni = cele(ev.currentTarget.value) || 30; } },
      DNEVI.map(([d, t]) => h("option", { value: String(d) }, t)));
    dniIzbira.value = String(formDni);
    const obsegIzbira = h("select", { id: "ag_obseg", "aria-label": "Obseg žetona", onchange: (ev) => { formObseg = ev.currentTarget.value === "beri+predlagaj" ? "beri+predlagaj" : "beri"; } },
      OBSEGI.map(([v, t]) => h("option", { value: v }, t)));
    obsegIzbira.value = formObseg;
    const telo = [
      h("p", { class: "telo-opomba" },
        "Žeton za Claude: branje dogodkov, prodaje, računov, opozoril in dnevnika dejanj. Agent ne vidi e-naslovov, imen ali telefonov kupcev in sam ničesar ne spreminja; ",
        "z obsegom »predlogi« lahko predlaga urejanje, objavo ali ustavitev prodaje, ki se izvede šele, ko ga potrdiš v zavihku »Čaka potrditev«. ",
        "Žeton velja na /agent/api/*, drugje je zavrnjen. Preklic velja takoj; vse naenkrat izklopi AGENT_API=0 na Renderju."),
      podatki && podatki.agent_api === false ? h("div", { class: "opozorilo", role: "alert" }, "Agent API je izklopljen (AGENT_API=0 na Renderju): vsi klici agenta dobijo 503.") : null,
      okvirZetona(),
      h("div", { class: "ag-obrazec" },
        h("label", {}, h("small", {}, "ime (kje je žeton vpisan)"), imePolje),
        h("label", {}, h("small", {}, "velja"), dniIzbira),
        h("label", {}, h("small", {}, "obseg"), obsegIzbira),
        h("button", { type: "button", onclick: ustvari }, "Ustvari žeton")),
      items.length ? h("div", { class: "rc-seznam" }, items.map(kartica)) : h("div", { class: "prazno" }, podatki ? "Ni žetonov." : "Nalagam …"),
    ];
    koren.replaceChildren(h("div", { class: "skupina" },
      h("h2", {}, "Agent", h("span", { class: "desno" }, h("button", { class: "tih mali", type: "button", onclick: () => window.naloziAgenta() }, "Osveži"))),
      h("div", { class: "telo" }, telo)));
  }

  async function osvezi() {
    await varno(async () => {
      podatki = await klic("GET", "/admin/api/agent-zetoni");
      narisi();
    });
  }

  async function ustvari() {
    const ime = formIme.trim();
    if (!ime) { obvesti("Vpiši ime žetona.", "slabo"); return; }
    if (ime.length > 60) { obvesti("Ime je predolgo (največ 60 znakov).", "slabo"); return; }
    const dni = formDni;
    const obseg = formObseg === "beri+predlagaj" ? ["beri", "predlagaj"] : ["beri"];
    const izid = await potrdi({
      naslov: "Ustvarim žeton za agenta?", potrdiBesedilo: "Ustvari žeton", razlog: "obvezen",
      vsebina: [h("p", {}, `Žeton »${ime}« bo veljal ${dni} dni in dovoli branje (dogodki, prodaja, računi, opozorila, dnevnik). Brez osebnih podatkov kupcev.`),
        obseg.includes("predlagaj") ? h("p", {}, "Dovoli tudi PREDLOGE (urejanje besedila, plakata in žanrov, okno prodaje, objava, ustavitev in zagon prodaje, nov osnutek, podvajanje). Nič se ne izvede brez tvoje potrditve v »Čaka potrditev«; cene, odpovedi, vračil in vlog agent ne more predlagati.") : null,
        h("p", {}, "Prikazan bo samo enkrat. Vpiši ga v nastavitve okolja Claude Code (Network secrets), ne v chat.")],
    });
    if (!izid) return;
    await varno(async () => {
      const d = await klic("POST", "/admin/api/agent-zetoni", { ime, dni, obseg, reason: izid.razlog });
      prikazanZeton = { zeton: String(d.zeton), ime: String(d.ime) };
      podatki = await klic("GET", "/admin/api/agent-zetoni");
      narisi();
    });
  }

  async function preklici(z) {
    const izid = await potrdi({
      naslov: "Prekličem žeton?", nevarno: true, potrdiBesedilo: "Prekliči žeton", razlog: "obvezen",
      vsebina: [h("p", {}, `Žeton »${z.ime}« (#${cele(z.id)}) bo takoj nehal veljati. Agent s tem žetonom bo dobil 401.`)],
    });
    if (!izid) return;
    await varno(async () => {
      await klic("POST", `/admin/api/agent-zetoni/${cele(z.id)}/preklici`, { reason: izid.razlog });
      obvesti("Žeton je preklican.", "ok");
      await osvezi();
    });
  }

  // klic iz zavihkov (index.html): osvezitev zavihka ZAPRE okvir z zetonom
  window.naloziAgenta = async function () {
    prikazanZeton = null;
    if (!podatki) narisi();
    await osvezi();
  };
})();
