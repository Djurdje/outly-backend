// Admin panel, zavihek »Dogodki« (faza 1, 21. 10. 2026): seznam z iskanjem in filtri, urejevalnik vseh polj (PATCH /events/:id), stikalo prodaje
// (sales_paused, migracija 055, I53), potrditvena okna (dialog.js, ne window.confirm), zgodovina sprememb (admin_dejanja).
// Brez ogrodja in brez gradnje (DECISIONS 21. 10. 2026). Uporablja globalne funkcije iz index.html: klic, obvesti, varno, h, datum, $, naloziPregled.
// XSS: podatki v DOM SAMO prek h() / textContent; brez innerHTML z nizi (test_admin_xss.js preverja ta odsek).
// Povezava na dogodek: #/dogodki/35 (deljiva, deluje tudi po osvezitvi strani).
// ---------- dogodki ----------
(function () {
  "use strict";
  const STANJA = { published: ["objavljen", "ok"], draft: ["osnutek", "siva"], cancelled: ["odpovedan", "slabo"] };
  const POLJA = {   // ime v dnevniku -> berljivo ime
    title: "Naslov", description: "Opis", poster_url: "Plakat", start_at: "Začetek", end_at: "Konec", min_age: "Starost", genres: "Žanri",
    status: "Stanje", ticket_price_cents: "Cena vstopnice", currency: "Valuta", ticket_url: "Zunanja prodaja", capacity: "Kapaciteta",
    recap_video_url: "Posnetek", sales_paused: "Prodaja", venue_club_id: "Gostitelj", venue_name: "Prizorišče", venue_address: "Naslov prizorišča",
    venue_city: "Mesto prizorišča", venue_lat: "Lat", venue_lng: "Lng",
  };
  let vsi = [], zanri = null, trenutni = null;

  // --- pomozne ---
  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);
  // Celi centi -> "12,50 €" brez deljenja s plavajočo vejico (I9).
  function cena(c, valuta) {
    if (c === null || c === undefined) return "brez vstopnic";
    const x = cele(c), v = valuta && String(valuta).toUpperCase() !== "EUR" ? " " + String(valuta).toUpperCase().slice(0, 3) : " €";
    return Math.floor(x / 100) + "," + String(x % 100).padStart(2, "0") + v;
  }
  // "12,50" / "12.5" / "12" -> 1250; "" -> null; sicer NaN. Brez plavajoče vejice.
  function centi(niz) {
    const s = String(niz || "").trim();
    if (s === "") return null;
    const m = /^(\d{1,6})(?:[.,](\d{1,2}))?$/.exec(s);
    if (!m) return NaN;
    return Number(m[1]) * 100 + Number((m[2] || "0").padEnd(2, "0"));
  }
  const vCentih = (c) => (c === null || c === undefined ? "" : Math.floor(cele(c) / 100) + "," + String(cele(c) % 100).padStart(2, "0"));
  // ISO -> vrednost za <input type=datetime-local> v lokalnem času brskalnika.
  function lokalno(iso) {
    if (!iso) return "";
    const d = new Date(iso); if (Number.isNaN(d.getTime())) return "";
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  }
  const izLokalnega = (v) => (v ? new Date(v).toISOString() : null);
  function znacka(status) { const s = STANJA[status] || [String(status || "?"), "siva"]; return h("span", { class: "znacka " + s[1] }, s[0]); }
  function prodaja(x) {
    if (x.status !== "published") return h("span", { class: "dg-prodaja ne" }, "ni objavljen");
    if (x.sales_paused) return h("span", { class: "dg-prodaja ustavljena" }, "ustavljena");
    if (x.ticket_price_cents === null || x.ticket_price_cents === undefined) return h("span", { class: "dg-prodaja ne" }, x.ticket_url ? "zunanja prodaja" : "brez vstopnic");
    if (x.capacity && cele(x.sold_count) >= cele(x.capacity)) return h("span", { class: "dg-prodaja ne" }, "razprodano");
    if (new Date(x.start_at).getTime() < Date.now()) return h("span", { class: "dg-prodaja ne" }, "začel se je");
    return h("span", { class: "dg-prodaja" }, "teče");
  }
  function vrednostZaPrikaz(k, v) {
    if (v === null || v === undefined || v === "") return "—";
    if (k === "ticket_price_cents") return cena(v);
    if (k === "sales_paused") return v ? "ustavljena" : "teče";
    if (k === "status") return (STANJA[v] || [String(v)])[0];
    if (k === "start_at" || k === "end_at") return datum(v);
    if (Array.isArray(v)) return v.join(", ") || "—";
    const s = String(v);
    return s.length > 80 ? s.slice(0, 77) + "…" : s;
  }
  function prejPotem(spremembe) {
    return h("div", { class: "prej-potem" }, spremembe.flatMap(([k, a, b]) => [
      h("b", {}, POLJA[k] || k), h("span", {}, h("s", {}, vrednostZaPrikaz(k, a)), " → ", vrednostZaPrikaz(k, b))]));
  }

  // --- usmerjanje (#/dogodki ali #/dogodki/35) ---
  function idIzHasha() { const m = /^#\/dogodki\/(\d{1,10})$/.exec(location.hash); return m ? Number(m[1]) : null; }
  function pojdi(id) {
    const cilj = id ? "#/dogodki/" + id : "#/dogodki";
    if (location.hash !== cilj) history.pushState(null, "", cilj);
    narisi();
  }
  window.addEventListener("popstate", () => { if (!$("panel").classList.contains("skrito") && /^#\/dogodki/.test(location.hash)) pokaziZavihek("dogodki"); });

  async function narisi() {
    const id = idIzHasha();
    if (id) await odpri(id); else await seznam();
  }
  window.naloziDogodke = narisi;

  // --- seznam ---
  function filtri() {
    const f = { q: $("dg_q").value.trim().toLowerCase(), status: $("dg_status").value, prodaja: $("dg_prodaja").value, klub: $("dg_klub").value, prihajajoci: $("dg_prih").checked };
    try { sessionStorage.setItem("outly_admin_dg_filtri", JSON.stringify(f)); } catch (_) {}
    return f;
  }
  function obnoviFiltre() {
    let f = null; try { f = JSON.parse(sessionStorage.getItem("outly_admin_dg_filtri") || "null"); } catch (_) {}
    if (!f) return;
    $("dg_q").value = f.q || ""; $("dg_status").value = f.status || ""; $("dg_prodaja").value = f.prodaja || ""; $("dg_prih").checked = !!f.prihajajoci;
    $("dg_klub").dataset.zelen = f.klub || "";
  }
  function ujema(x, f) {
    if (f.status && x.status !== f.status) return false;
    if (f.klub && String(x.club_id) !== f.klub) return false;
    if (f.prihajajoci && new Date(x.end_at || x.start_at).getTime() < Date.now() - 6 * 3600 * 1000) return false;
    if (f.prodaja === "ustavljena" && !x.sales_paused) return false;
    if (f.prodaja === "tece" && (x.sales_paused || x.status !== "published")) return false;
    if (f.q && !(`${x.title} ${x.club_name} ${x.id} ${x.venue_name || ""} ${x.venue_city || ""}`.toLowerCase().includes(f.q))) return false;
    return true;
  }
  function narisiSeznam() {
    const f = filtri();
    const zad = vsi.filter((x) => ujema(x, f));
    $("dg_stevec").textContent = `${zad.length} od ${vsi.length}`;
    const el = $("dTabela");
    if (!zad.length) { el.replaceChildren(h("div", { class: "prazno" }, vsi.length ? "Noben dogodek ne ustreza filtrom." : "Ni dogodkov.")); return; }
    const vrstice = zad.map((x) => {
      const tr = h("tr", { class: "dg-vrstica", tabindex: "0" },
        h("td", { class: "mono dg-id" }, String(cele(x.id))),
        h("td", { class: "dg-naslov" }, h("b", {}, x.title), h("span", { class: "drobno" }, [x.club_name, x.club_hidden ? "klub skrit" : ""].filter(Boolean).join(" – "))),
        h("td", { class: "mono dg-cas" }, datum(x.start_at)),
        h("td", { class: "mono" }, cena(x.ticket_price_cents, x.currency), h("span", { class: "drobno" }, x.capacity ? `${cele(x.sold_count)} / ${cele(x.capacity)}` : `${cele(x.sold_count)} prodanih`)),
        h("td", {}, prodaja(x)),
        h("td", {}, znacka(x.status)));
      tr.onclick = () => pojdi(cele(x.id));
      tr.onkeydown = (e) => { if (e.key === "Enter") pojdi(cele(x.id)); };
      return tr;
    });
    el.replaceChildren(h("table", { class: "dg-tabela" },
      h("thead", {}, h("tr", {}, ["#", "Dogodek", "Začetek", "Cena / prodano", "Prodaja", "Stanje"].map((g) => h("th", {}, g)))),
      h("tbody", {}, vrstice)));
  }
  async function seznam() {
    $("dg_seznam").classList.remove("skrito"); $("dg_urejevalnik").classList.add("skrito");
    if (!$("dg_q").dataset.vezan) {
      $("dg_q").dataset.vezan = "1"; obnoviFiltre();
      for (const id of ["dg_q", "dg_status", "dg_prodaja", "dg_klub", "dg_prih"]) { $(id).oninput = narisiSeznam; $(id).onchange = narisiSeznam; }
      $("dg_osvezi").onclick = seznam;
    }
    await varno(async () => {
      vsi = await klic("GET", "/admin/api/events");
      const klubi = new Map(vsi.map((x) => [String(x.club_id), x.club_name]));
      const izbran = $("dg_klub").value || $("dg_klub").dataset.zelen || "";
      $("dg_klub").replaceChildren(h("option", { value: "" }, "vsi klubi"),
        [...klubi].sort((a, b) => String(a[1]).localeCompare(String(b[1]), "sl")).map(([id, ime]) => h("option", { value: id }, ime)));
      $("dg_klub").value = klubi.has(izbran) ? izbran : "";
      narisiSeznam();
    });
  }

  // --- urejevalnik ---
  function polje(id, oznaka, vnos, pomoc, siroko) {
    vnos.id = id;
    return h("div", { class: siroko ? "siroko" : "" }, h("label", { for: id }, oznaka), vnos, pomoc ? h("span", { class: "pomoc" }, pomoc) : null);
  }
  const vnos = (lastnosti) => h("input", lastnosti || {});

  // Vrednosti obrazca v obliki PATCH /events/:id (camelCase); primerjava s trenutnim dogodkom da samo spremenjena polja.
  function izObrazca() {
    const v = (id) => $(id).value;
    return {
      title: v("dge_title").trim(), description: v("dge_description"), posterUrl: v("dge_poster").trim(),
      startAt: izLokalnega(v("dge_start")), endAt: izLokalnega(v("dge_end")), minAge: v("dge_minAge").trim() === "" ? NaN : Number(v("dge_minAge")),
      genres: [...document.querySelectorAll("#dge_genres input:checked")].map((x) => x.value),
      ticketPriceCents: centi(v("dge_price")), currency: v("dge_currency").trim().toUpperCase(), ticketUrl: v("dge_ticketUrl").trim(),
      capacity: v("dge_capacity").trim() === "" ? null : Number(v("dge_capacity")),
      recapVideoUrl: v("dge_recap").trim(),
      venueName: v("dge_venueName").trim(), venueAddress: v("dge_venueAddress").trim(), venueCity: v("dge_venueCity").trim(),
    };
  }
  const KLJUCI = [   // camel -> snake (dogodek iz GET /admin/api/events/:id)
    ["title", "title"], ["description", "description"], ["posterUrl", "poster_url"], ["startAt", "start_at"], ["endAt", "end_at"], ["minAge", "min_age"],
    ["genres", "genres"], ["ticketPriceCents", "ticket_price_cents"], ["currency", "currency"], ["ticketUrl", "ticket_url"], ["capacity", "capacity"],
    ["recapVideoUrl", "recap_video_url"], ["venueName", "venue_name"], ["venueAddress", "venue_address"], ["venueCity", "venue_city"],
  ];
  const enako = (k, a, b) => {
    if (k === "start_at" || k === "end_at") return (a ? Math.floor(new Date(a).getTime() / 60000) : null) === (b ? Math.floor(new Date(b).getTime() / 60000) : null);
    if (k === "genres") return JSON.stringify([...(a || [])].sort()) === JSON.stringify([...(b || [])].sort());
    if (k === "currency") return String(a || "").trim().toUpperCase() === String(b || "").trim().toUpperCase();
    return JSON.stringify(a ?? null) === JSON.stringify(b ?? null) || ((a ?? "") === "" && (b ?? "") === "");
  };
  function spremembe() {
    const f = izObrazca(), e = trenutni.event, telo = {}, seznamS = [];
    for (const [c, s] of KLJUCI) {
      if (enako(s, e[s], f[c])) continue;
      telo[c] = f[c]; seznamS.push([s, e[s], f[c]]);
    }
    // Prizorisce: streznik ga preveri celega (organizator rabi ime + mesto); pri spremembi poslji vsa tri polja.
    if (["venueName", "venueAddress", "venueCity"].some((k) => k in telo)) { telo.venueName = f.venueName; telo.venueAddress = f.venueAddress; telo.venueCity = f.venueCity; }
    return { telo, seznamS };
  }
  function oznaciSpremenjeno() {
    if (!trenutni) return;
    const { seznamS } = spremembe();
    const sprem = new Set(seznamS.map((x) => x[0]));
    for (const [c, s] of KLJUCI) {
      const id = { title: "dge_title", description: "dge_description", posterUrl: "dge_poster", startAt: "dge_start", endAt: "dge_end", minAge: "dge_minAge", genres: "dge_genres",
        ticketPriceCents: "dge_price", currency: "dge_currency", ticketUrl: "dge_ticketUrl", capacity: "dge_capacity", recapVideoUrl: "dge_recap",
        venueName: "dge_venueName", venueAddress: "dge_venueAddress", venueCity: "dge_venueCity" }[c];
      const ovoj = $(id) && $(id).parentElement;
      if (ovoj) ovoj.classList.toggle("spremenjeno", sprem.has(s));
    }
    $("dge_shrani").disabled = !seznamS.length;
    $("dge_stanje").textContent = seznamS.length ? `Neshranjenih sprememb: ${seznamS.length}` : "Vse je shranjeno.";
    const pu = $("dge_poster").value.trim();
    const img = $("dge_plakatSlika");
    if (/^https:\/\//.test(pu)) { img.src = pu; img.classList.remove("skrito"); } else img.classList.add("skrito");
  }

  function stikalo(e) {
    const ustavljena = !!e.sales_paused;
    const b = h("button", { type: "button", id: "dge_stikalo", class: "dg-stikalo" + (ustavljena ? " ustavljena" : ""), "aria-pressed": ustavljena ? "false" : "true" },
      h("span", { class: "tir", "aria-hidden": "true" }),
      h("span", {}, h("b", {}, ustavljena ? "Prodaja ustavljena" : "Prodaja teče"),
        h("span", { class: "pod" }, ustavljena ? "Kupci ne morejo kupiti vstopnic ne miz. Cena ostane vidna." : "Kupci lahko kupijo vstopnice in VIP mize.")),
      h("span", { class: "akcija" }, ustavljena ? "Zaženi prodajo" : "Ustavi prodajo"));
    b.onclick = () => preklopiProdajo(!ustavljena);
    return b;
  }
  async function preklopiProdajo(ustavi) {
    const e = trenutni.event, s = trenutni.stats;
    const ok = await potrdi(ustavi ? {
      naslov: "Ustavim prodajo?", nevarno: true, potrdiBesedilo: "Ustavi prodajo", razlog: "neobvezen",
      vsebina: [h("p", {}, `»${e.title}«: nakup vstopnic, VIP miz in nakup brez računa takoj vrne napako. Cena (${cena(e.ticket_price_cents, e.currency)}) ostane.`),
        h("p", {}, cele(s.pending_orders) > 0
          ? `Odprtih plačil: ${cele(s.pending_orders)}. Odprta plačilna okna se zaprejo in teh nakupov ni več mogoče plačati. Če kdo plača v istem trenutku, mu denar vrnemo samodejno.`
          : "Odprtih plačil ni."),
        h("p", {}, "Že plačane vstopnice ostanejo veljavne, skeniranje na vratih teče naprej.")],
    } : {
      naslov: "Zaženem prodajo?", potrdiBesedilo: "Zaženi prodajo", razlog: "neobvezen",
      vsebina: [h("p", {}, `»${e.title}«: kupci lahko spet kupijo vstopnice (${cena(e.ticket_price_cents, e.currency)}) in VIP mize.`)],
    });
    if (!ok) return;
    $("dge_stikalo").disabled = true;
    await varno(async () => {
      await klic("PATCH", "/events/" + cele(e.id), { salesPaused: ustavi });
      obvesti(ustavi ? "Prodaja ustavljena. Odprta plačilna okna se zapirajo." : "Prodaja spet teče.", "ok");
    });
    await odpri(cele(e.id));
  }

  async function spremeniStanje(novo) {
    const e = trenutni.event, s = trenutni.stats;
    let ok;
    if (novo === "cancelled") {
      const n = cele(s.paid_orders), nt = cele(s.test_paid_orders);
      ok = await potrdi({
        naslov: "Odpovem dogodek?", nevarno: true, potrdiBesedilo: "Odpovej dogodek", vpis: "ODPOVEJ", razlog: "obvezen",
        vsebina: [h("p", {}, `»${e.title}« bo odpovedan in ne bo več viden v aplikaciji.`),
          n > 0 ? h("p", {}, h("b", {}, `${n} plačanih naročil (${cena(s.paid_cents)})`), " dobi denar samodejno v celoti nazaj, vstopnice prenehajo veljati, kupci dobijo e-pošto. Vračil po izvedbi ni mogoče preklicati.")
            : h("p", {}, "Pravih plačanih naročil ni, zato noben kupec ne dobi vračila."),
          nt > 0 ? h("p", {}, `Še ${nt} testnih naročil (${cena(s.test_paid_cents)}, ni pravi denar).`) : null],
      });
      if (!ok) return;
      await varno(async () => { await klic("PATCH", "/admin/api/events/" + cele(e.id), { status: "cancelled", reason: ok.razlog }); obvesti(`»${e.title}« odpovedan.`, "ok"); naloziPregled(); });
    } else {
      ok = await potrdi({
        naslov: novo === "published" ? "Objavim dogodek?" : "Premaknem med osnutke?", potrdiBesedilo: novo === "published" ? "Objavi" : "Premakni med osnutke",
        vsebina: novo === "published" ? [h("p", {}, `»${e.title}« bo viden v aplikaciji. Sledilci kluba dobijo obvestilo.`)]
          : [h("p", {}, `»${e.title}« ne bo več viden v aplikaciji. Plačane vstopnice ostanejo veljavne.`)],
      });
      if (!ok) return;
      await varno(async () => { await klic("PATCH", "/events/" + cele(e.id), { status: novo }); obvesti(novo === "published" ? `»${e.title}« objavljen.` : `»${e.title}« je osnutek.`, "ok"); });
    }
    await odpri(cele(e.id));
  }

  async function shrani() {
    const { telo, seznamS } = spremembe();
    if (!seznamS.length) return;
    if (Number.isNaN(telo.ticketPriceCents)) return obvesti("Cena: vpiši znesek, npr. 12,50 (prazno = brez vstopnic na Outlyju).", "slabo");
    if ("minAge" in telo && !(Number.isInteger(telo.minAge) && telo.minAge >= 0 && telo.minAge <= 99)) return obvesti("Starost: celo število 0–99.", "slabo");
    if ("capacity" in telo && telo.capacity !== null && !(Number.isInteger(telo.capacity) && telo.capacity >= 1)) return obvesti("Kapaciteta: celo število od 1 naprej (prazno = brez omejitve).", "slabo");
    if (!telo.startAt && "startAt" in telo) return obvesti("Začetek je obvezen.", "slabo");
    // Raven 2 (načrt 3.2): cena, kapaciteta, datum, valuta potrebujejo potrditev s »prej → potem«; besedilo, plakat, žanri ne.
    const obcutljivo = seznamS.filter(([k]) => ["ticket_price_cents", "capacity", "start_at", "end_at", "currency", "ticket_url"].includes(k));
    if (obcutljivo.length) {
      const brezCene = "ticketPriceCents" in telo && telo.ticketPriceCents === null;
      const ok = await potrdi({ naslov: "Shranim spremembe?", potrdiBesedilo: "Shrani", nevarno: brezCene,
        vsebina: [prejPotem(seznamS),
          brezCene ? h("p", {}, "Prazna cena pomeni, da dogodek nima več vstopnic na Outlyju. Za začasno ustavitev raje uporabi stikalo »Ustavi prodajo«.") : null,
          seznamS.some(([k]) => k === "ticket_price_cents") && !brezCene ? h("p", {}, "Nova cena velja za nove nakupe. Kdor ima odprto plačilo, plača ceno, ki jo je videl.") : null] });
      if (!ok) return;
    }
    $("dge_shrani").disabled = true;
    let uspelo = false;
    await varno(async () => {
      try {
        await klic("PATCH", "/events/" + cele(trenutni.event.id), telo);
        uspelo = true;
        obvesti("Shranjeno.", "ok");
      } catch (err) {
        if (/capacity_below_sold|^400: Capacity can't be lower/i.test(err.message)) throw new Error(`Kapaciteta ne sme biti pod številom prodanih vstopnic (${cele(trenutni.event.sold_count)}).`);
        throw err;
      }
    });
    // Ob napaki obrazec OSTANE (vpisane spremembe se ne izgubijo); ob uspehu ga znova preberemo (nove vrednosti + zgodovina).
    if (uspelo) await odpri(cele(trenutni.event.id)); else oznaciSpremenjeno();
  }

  function zgodovina(vrstice) {
    if (!vrstice.length) return h("div", { class: "prazno" }, "Admin tega dogodka še ni spreminjal.");
    const IME = { "event.update": "Urejeno", "event.publish": "Objavljeno", "event.unpublish": "Med osnutke", "event.cancel": "Odpovedano", "event.delete": "Izbrisano",
      "event.sales_pause": "Prodaja ustavljena", "event.sales_resume": "Prodaja spet teče" };
    return h("ul", { class: "dg-zgodovina" }, vrstice.map((a) => {
      const prej = a.prej || {}, potem = a.potem || {};
      const kljuci = [...new Set([...Object.keys(prej), ...Object.keys(potem)])];
      return h("li", {},
        h("b", {}, IME[a.dejanje] || a.dejanje), " ", h("span", { class: "kdo" }, `${datum(a.cas)} – ${a.admin_email || "izbrisan admin"}`),
        kljuci.map((k) => h("span", { class: "sprememba" }, (POLJA[k] || k) + ": ", h("s", {}, vrednostZaPrikaz(k, prej[k])), " → ", vrednostZaPrikaz(k, potem[k]))),
        a.razlog ? h("span", { class: "razlog" }, "Razlog: " + a.razlog) : null);
    }));
  }

  async function odpri(id) {
    $("dg_seznam").classList.add("skrito"); $("dg_urejevalnik").classList.remove("skrito");
    const okvir = $("dg_urejevalnik");
    if (!trenutni || cele(trenutni.event.id) !== id) okvir.replaceChildren(h("div", { class: "prazno" }, "Nalagam dogodek …"));
    await varno(async () => {
      if (!zanri) { try { zanri = (await klic("GET", "/genres")).genres || []; } catch (_) { zanri = []; } }
      let d;
      try { d = await klic("GET", "/admin/api/events/" + id); }
      catch (err) {
        if (/^404/.test(err.message)) { okvir.replaceChildren(h("div", { class: "prazno" }, "Dogodek ne obstaja (morda je bil izbrisan).")); return; }
        throw err;
      }
      trenutni = d;
      const e = d.event, s = d.stats;
      const nazaj = h("button", { type: "button", class: "dg-nazaj" }, "‹ Vsi dogodki"); nazaj.onclick = () => pojdi(null);
      const gumbi = [];
      if (e.status !== "published") { const g = h("button", { type: "button", class: "dobro mali" }, "Objavi"); g.onclick = () => spremeniStanje("published"); gumbi.push(g); }
      if (e.status === "published") { const g = h("button", { type: "button", class: "tih mali" }, "Med osnutke"); g.onclick = () => spremeniStanje("draft"); gumbi.push(g); }
      if (e.status !== "cancelled") { const g = h("button", { type: "button", class: "nevarno mali" }, "Odpovej dogodek"); g.onclick = () => spremeniStanje("cancelled"); gumbi.push(g); }

      const zanriPolje = h("div", { id: "dge_genres", class: "vrsta", role: "group", "aria-label": "Žanri" },
        [...new Set([...zanri, ...(e.genres || [])])].map((z) => {
          const cb = h("input", { type: "checkbox", value: z, style: "width:auto;min-height:0" }); cb.checked = (e.genres || []).includes(z);
          return h("label", { style: "display:flex;gap:5px;align-items:center;text-transform:none;letter-spacing:0;font-weight:500;color:var(--ink);margin:0 10px 0 0" }, cb, z);
        }));
      const opis = h("textarea", { rows: "4" }); opis.value = e.description || "";
      const naslov = vnos({ maxlength: "200" }); naslov.value = e.title || "";
      const plakat = vnos({ placeholder: "https://res.cloudinary.com/…", inputmode: "url" }); plakat.value = e.poster_url || "";
      const zac = vnos({ type: "datetime-local" }); zac.value = lokalno(e.start_at);
      const kon = vnos({ type: "datetime-local" }); kon.value = lokalno(e.end_at);
      const starost = vnos({ inputmode: "numeric" }); starost.value = String(e.min_age ?? "");
      const cenaV = vnos({ inputmode: "decimal", placeholder: "prazno = brez vstopnic" }); cenaV.value = vCentih(e.ticket_price_cents);
      const valuta = vnos({ maxlength: "3", style: "text-transform:uppercase" }); valuta.value = e.currency || "EUR";
      const zun = vnos({ placeholder: "https://", inputmode: "url" }); zun.value = e.ticket_url || "";
      const kap = vnos({ inputmode: "numeric", placeholder: "brez omejitve" }); kap.value = e.capacity === null || e.capacity === undefined ? "" : String(e.capacity);
      const posnetek = vnos({ placeholder: "https://", inputmode: "url" }); posnetek.value = e.recap_video_url || "";
      const vIme = vnos(); vIme.value = e.venue_name || "";
      const vNaslov = vnos(); vNaslov.value = e.venue_address || "";
      const vMesto = vnos(); vMesto.value = e.venue_city || "";

      const shraniG = h("button", { type: "button", id: "dge_shrani" }, "Shrani spremembe"); shraniG.onclick = shrani;
      const zavrzi = h("button", { type: "button", class: "tih" }, "Zavrzi"); zavrzi.onclick = () => { trenutni = null; odpri(id); };
      const img = h("img", { id: "dge_plakatSlika", class: "dg-plakat skrito", alt: "Predogled plakata" });

      okvir.replaceChildren(
        h("div", { class: "skupina" },
          h("div", { class: "dg-glava" },
            h("div", { style: "flex:1 1 260px;min-width:0" }, nazaj,
              h("h2", {}, e.title, h("span", { class: "drobno" }, `#${cele(e.id)} – ${e.club_name}${e.club_hidden ? " (klub skrit)" : ""} – ${datum(e.start_at)}`))),
            h("div", { class: "vrsta" }, znacka(e.status), gumbi)),
          h("div", { class: "telo" }, e.status === "published" ? stikalo(e)
            : h("p", { style: "margin:0;font-size:13px;color:var(--muted)" }, e.status === "cancelled" ? "Dogodek je odpovedan, prodaje ni." : "Osnutek ni viden v aplikaciji, prodaje ni.",
              e.sales_paused ? " Ob objavi bo prodaja ustavljena (stikalo)." : "")),
          h("div", { class: "dg-stevilke" },
            h("div", {}, h("b", {}, e.capacity ? `${cele(e.sold_count)} / ${cele(e.capacity)}` : String(cele(e.sold_count))), h("span", {}, "prodanih vstopnic")),
            h("div", {}, h("b", {}, String(cele(s.checked_in))), h("span", {}, "na vratih")),
            h("div", {}, h("b", {}, cena(s.paid_cents)), h("span", {}, `${cele(s.paid_orders)} plačanih naročil`)),
            h("div", {}, h("b", {}, String(cele(s.pending_orders))), h("span", {}, "odprtih plačil")),
            cele(s.test_paid_orders) ? h("div", {}, h("b", {}, cena(s.test_paid_cents)), h("span", {}, `${cele(s.test_paid_orders)} testnih (ni pravi denar)`)) : null)),
        h("div", { class: "skupina dg-obrazec" }, h("h2", {}, "Podatki dogodka"),
          h("div", { class: "telo" },
            h("div", { class: "polja" },
              polje("dge_title", "Naslov", naslov, null, true),
              polje("dge_start", "Začetek", zac), polje("dge_end", "Konec", kon, "Večdnevni dogodek mora imeti konec."),
              polje("dge_price", "Cena vstopnice (€)", cenaV, "Za začasno ustavitev uporabi stikalo, ne briši cene."),
              polje("dge_capacity", "Kapaciteta", kap, `Najmanj ${cele(e.sold_count)} (že prodano).`),
              polje("dge_currency", "Valuta", valuta), polje("dge_minAge", "Najnižja starost", starost),
              polje("dge_ticketUrl", "Zunanja prodaja (URL)", zun, "Samo, če vstopnic ne prodaja Outly.", true),
              h("div", { class: "siroko" }, h("label", { for: "dge_poster" }, "Plakat (URL)"), h("div", { class: "vrsta", style: "align-items:flex-start;flex-wrap:nowrap" }, img, plakat)),
              polje("dge_description", "Opis", opis, null, true),
              h("div", { class: "siroko" }, h("label", {}, "Žanri"), zanriPolje),
              polje("dge_venueName", "Prizorišče (prosto vpisano)", vIme, e.venue_club_id ? "Dogodek gostuje pri klubu na Outlyju; vpis prizorišča to zamenja." : null),
              polje("dge_venueAddress", "Naslov prizorišča", vNaslov), polje("dge_venueCity", "Mesto prizorišča", vMesto),
              polje("dge_recap", "Posnetek po dogodku (https)", posnetek, "Samo končan dogodek med tremi najbolj prodanimi v klubu.", true))),
          h("div", { class: "dg-shrani" }, shraniG, zavrzi, h("span", { id: "dge_stanje", class: "stanje", "aria-live": "polite" }))),
        h("div", { class: "skupina" }, h("h2", {}, "Zgodovina sprememb"), zgodovina(d.audit || [])));
      for (const [vn, idp] of [[naslov, "dge_title"], [opis, "dge_description"], [plakat, "dge_poster"], [zac, "dge_start"], [kon, "dge_end"], [starost, "dge_minAge"],
        [cenaV, "dge_price"], [valuta, "dge_currency"], [zun, "dge_ticketUrl"], [kap, "dge_capacity"], [posnetek, "dge_recap"], [vIme, "dge_venueName"], [vNaslov, "dge_venueAddress"], [vMesto, "dge_venueCity"]]) {
        vn.id = idp; vn.oninput = oznaciSpremenjeno;
      }
      zanriPolje.onchange = oznaciSpremenjeno;
      oznaciSpremenjeno();
    });
  }
})();
// ---------- konec dogodkov ----------
