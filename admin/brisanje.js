// Admin panel: pravo brisanje dogodka, kluba in promo kode (Martin, 24. 10. 2026; invarianta I63, strezniski modul admin_brisanje.js).
// Pred vsakim brisanjem panel vpraša strežnik (GET .../delete-check, nic se ne spremeni): ce strežnik brisanje zavrne (pravi promet, racuni, spori, Stripova vracila,
// uradni profil ...), panel namesto »Izbriši« razloži zakaj in pri dogodku ponudi obstojeco »Odpovej«. Sicer potrditveno okno (dialog.js) pokaze, kaj bo izginilo,
// zahteva vpis IZBRISI in razlog (gre v dnevnik admin dejanj). Odlocitev je VEDNO streznikova (DELETE ponovno preveri vse, 409 ob blokadi).
// Uporablja globalne funkcije iz index.html: klic, h, obvesti, potrdi (dialog.js), klubi (seznam klubov). XSS: vse iz podatkov v DOM SAMO prek h() / textContent.
(function () {
  "use strict";
  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);
  const VPIS = "IZBRISI";
  const IMENA = {
    events: "dogodkov", orders: "naročil skupaj (testnih, neuspelih ali preklicanih)", real_failed_orders: "od tega pravih preklicanih/neuspelih brez plačila (seja potekla)", tickets: "vstopnic", guest_lists: "guest list", guest_list_members: "povabljenih na guest listah",
    club_tables: "miz", table_holds: "rezervacij miz", table_service: "strežb", vracila: "vračil (testnih)", spori: "sporov (testnih)", vracila_iz_stripa: "Stripovih vračil (testnih)",
    gost_zetoni: "žetonov gostov", ticket_transfers: "prenosov vstopnic", event_favorites: "priljubljenih", event_interest: "zanimanj", view_counts: "dnevnih ogledov",
    club_event_notifications: "obvestil", promo_code_events: "povezav s promo kodami", odpovedi_dogodkov: "zapisov o odpovedi", bottle_packages: "paketov steklenic",
    club_members: "članov ekipe", club_invites: "vabil v ekipo", club_follows: "sledilcev", promo_codes: "promo kod",
  };
  const VRSTNI_RED = Object.keys(IMENA);

  function razlogBlokade(b) {
    const n = cele(b.count);
    switch (b.code) {
      case "has_real_orders": return `Ima ${n} pravih naročil (plačanih, v teku ali vrnjenih). Pravi promet mora ostati, zato ga ni mogoče izbrisati.`;
      case "has_invoices": return `Obstaja ${n} davčnih računov za naročila. Računi so računovodski dokumenti in morajo ostati.`;
      case "has_disputes": return `Obstaja ${n} sporov (chargeback) za prava naročila. Morajo ostati.`;
      case "has_refunds": return `Obstaja ${n} vračil (tudi čakajočih ali neuspelih in Stripovih) za prava naročila: kupec utegne še čakati denar. Morajo ostati.`;
      case "payment_exists": return `${n} pravih preklicanih ali neuspelih naročil ima plačilo (PaymentIntent ali plačan znesek). Plačilo obstaja, dogodka ni mogoče izbrisati: odpovej ga, da kupci dobijo denar nazaj.`;
      case "checkout_may_complete": return `${n} pravih preklicanih ali neuspelih naročil ima Stripovo plačilno sejo, ki jo kupec utegne še plačati (webhooki 3 dni, odloženo plačilo SEPA 5–14 dni). Poskusi znova 3 dni po izteku seje ali dogodek odpovej.`;
      case "official_club": return "To je uradni profil Outly (ali klub z imenom Outly). Ni ga mogoče izbrisati.";
      case "venue_in_use": return `${n} neodpovedanih dogodkov drugih klubov ima ta klub za prizorišče. Najprej jih odpovej ali jim spremeni prizorišče.`;
      case "foreign_references": return `${n} naročil drugih dogodkov kaže na mizo, paket, guest listo ali klub, ki bi bil izbrisan.`;
      default: return "Brisanje ni dovoljeno.";
    }
  }
  const prazniBlokad = (r) => (Array.isArray(r && r.blockers) ? r.blockers : []);

  function seznamStevil(wd) {
    const vrstice = VRSTNI_RED.filter((k) => cele(wd && wd[k]) > 0).map((k) => h("li", {}, h("b", {}, String(cele(wd[k]))), " " + IMENA[k]));
    return vrstice.length ? h("ul", { class: "br-seznam" }, vrstice) : null;
  }

  // Okno »ni mogoče izbrisati«: razlogi + (pri dogodku) ponudba odpovedi. Vrne true, ce je admin izbral ponujeno dejanje.
  async function oknoBlokade(naslov, imeVrste, blokade, odpovej) {
    const ponudi = typeof odpovej === "function";
    const ok = await potrdi({
      naslov, potrdiBesedilo: ponudi ? "Odpovej dogodek" : "V redu",
      vsebina: [h("p", {}, `${imeVrste} ni mogoče izbrisati:`), h("ul", { class: "br-seznam" }, blokade.map((b) => h("li", {}, razlogBlokade(b)))),
        ponudi ? h("p", {}, "Namesto tega ga odpovej: kupci dobijo denar nazaj, naročila in računi ostanejo.") : null],
    });
    if (ok && ponudi) await odpovej();
    return !!ok;
  }
  const porocilo = (e) => String((e && e.message) || e).replace(/^\d+: /, "");

  // Skupni tok: predogled -> okno -> DELETE -> osvezitev.
  async function brisi({ checkUrl, deleteUrl, naslov, imeVrste, besedilo, odpovej, po, uspeh }) {
    let r;
    try { r = await klic("GET", checkUrl); } catch (e) { obvesti(porocilo(e), "slabo"); return; }
    if (!r.can_delete) { await oknoBlokade("Brisanje ni mogoče", imeVrste, prazniBlokad(r), odpovej); return; }
    const izid = await potrdi({
      naslov, nevarno: true, potrdiBesedilo: "Izbriši za vedno", vpis: VPIS, razlog: "obvezen",
      vsebina: [...besedilo(r), h("p", { class: "br-opozorilo" }, "Brisanja ni mogoče razveljaviti.")],
    });
    if (!izid) return;
    try {
      await klic("DELETE", deleteUrl, { reason: izid.razlog });
    } catch (e) {
      if (e && e.status === 409 && e.telo && Array.isArray(e.telo.blockers)) { await oknoBlokade("Brisanje ni mogoče", imeVrste, e.telo.blockers, odpovej); return; }
      if (e && e.status === 503) { obvesti("Zapis je trenutno v uporabi (nakup ali sken). Nič ni izbrisano, poskusi čez trenutek.", "slabo"); return; }
      obvesti(porocilo(e), "slabo"); return;
    }
    obvesti(uspeh, "ok");
    if (typeof po === "function") await po();
    if (typeof window.naloziPregled === "function") window.naloziPregled();
  }

  function dogodek(e, { odpovej, po } = {}) {
    const id = cele(e.id);
    return brisi({
      checkUrl: `/admin/api/events/${id}/delete-check`, deleteUrl: `/admin/api/events/${id}`, naslov: "Izbrišem dogodek za vedno?", imeVrste: `Dogodka »${e.title}«`,
      besedilo: (r) => [h("p", {}, `Dogodek »${e.title}« in vse, kar visi nanj, bo trajno izbrisano:`), seznamStevil(r.will_delete)],
      odpovej: e.status === "cancelled" ? null : odpovej, po, uspeh: `Dogodek »${e.title}« je izbrisan.`,
    });
  }

  function klub(k, { po } = {}) {
    const id = cele(k.id);
    return brisi({
      checkUrl: `/admin/api/clubs/${id}/delete-check`, deleteUrl: `/admin/api/clubs/${id}`, naslov: "Izbrišem klub za vedno?", imeVrste: `Kluba »${k.name}«`,
      besedilo: (r) => [h("p", {}, `Klub »${k.name}« z vsemi dogodki in vsem, kar visi nanj, bo trajno izbrisan:`),
        (r.events || []).length ? h("p", { class: "br-dogodki" }, "Dogodki: " + r.events.slice(0, 8).map((x) => x.title).join(", ") + (cele(r.events_total) > 8 ? ` … in še ${cele(r.events_total) - 8}` : "")) : null,
        seznamStevil(r.will_delete), h("p", {}, "Uporabniki (tudi lastnik in ekipa) ostanejo; lastnik ostane uporabnik brez kluba.")],
      odpovej: null, po, uspeh: `Klub »${k.name}« je izbrisan.`,
    });
  }

  function promo(k, { po } = {}) {
    const id = cele(k.id);
    return brisi({
      checkUrl: `/admin/api/promo-codes/${id}/delete-check`, deleteUrl: `/admin/api/promo-codes/${id}`, naslov: "Izbrišem promo kodo za vedno?", imeVrste: `Kode ${k.code}`,
      besedilo: (r) => [h("p", {}, `Koda ${k.code} bo trajno izbrisana (kupci je ne bodo mogli več vpisati).`),
        h("p", {}, cele(r.orders_using_code) > 0 ? `Kodo je uporabilo ${cele(r.orders_using_code)} naročil. Naročila in vstopnice ostanejo, izgine samo vez s kodo: statistika te kode izgine.` : "Kode ni uporabilo nobeno naročilo.")],
      odpovej: null, po, uspeh: `Koda ${k.code} je izbrisana.`,
    });
  }

  // Gumb v urejevalniku dogodka. Takoj se pokaze »Izbriši dogodek«; ko strežnik odgovori, da brisanje ni mogoče (pravi promet ...), ga zamenja razlaga, »Odpovej dogodek« pa ostane.
  function dogodekGumb(e, { odpovej, po } = {}) {
    const id = cele(e.id);
    const mesto = h("span", { class: "br-mesto" });
    const g = h("button", { type: "button", id: "dge_izbrisi", class: "nevarno mali" }, "Izbriši dogodek");
    g.onclick = () => dogodek(e, { odpovej, po });
    mesto.append(g);
    klic("GET", `/admin/api/events/${id}/delete-check?lite=1`).then((r) => {
      if (r && r.can_delete === false && mesto.isConnected !== false) {
        mesto.replaceChildren(h("span", { class: "br-opomba", id: "dge_izbris_ni" }, "Izbris ni mogoč: " + prazniBlokad(r).map(razlogBlokade).join(" ") + (e.status === "cancelled" ? "" : " Uporabi »Odpovej dogodek«.")));
      }
    }).catch(() => {});   // predogled je samo pomoč: ob napaki ostane gumb, odloča strežnik
    return mesto;
  }

  window.brisanje = { dogodek, klub, promo, dogodekGumb, razlogBlokade };
  window.kIzbrisi = (id) => {   // klic iz seznama klubov (index.html); id je ze cel() v atributu
    const k = (typeof klubi !== "undefined" ? klubi : []).find((x) => x.id === id);
    if (k) klub(k, { po: () => (typeof naloziKlube === "function" ? naloziKlube() : null) });
  };
})();
