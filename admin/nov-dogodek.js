// Admin panel, zavihek »Dogodki«: tok »ustvari → dopolni → preveri → objavi«, nalaganje plakata in podvajanje (#328, 23. 10. 2026; nacrt outly-hq
// docs/ideje/2026-10-23-admin-panel-nadgradnja.md 2.2). Kos 1: gumb »Nov dogodek« (5 polj → osnutek prek POST /admin/api/events). Kos 2: v urejevalniku »Naloži sliko« (podpis
// POST /uploads/cloudinary-signature, nalaganje neposredno na Cloudinary; od #400 dva plakata, 4:5 in 3:4, z izrezom s fiksnim razmerjem pred nalaganjem). Kos 3: »Pred objavo« (GET /admin/api/opozorila?dogodek=ID); rdeča ovira onemogoči »Objavi«.
// Kos 4: »Podvoji« (POST /admin/api/events/:id/duplicate, enkratno ali tedensko do 12 osnutkov).
// Brez ogrodja in brez gradnje (DECISIONS 21. 10. 2026). Uporablja globalne funkcije iz index.html in dialog.js: klic, obvesti, h, datum, $, potrdi, pokaziZavihek.
// XSS: podatki (naslov, ime kluba, besedilo opozorila) v DOM SAMO prek h() / textContent; brez innerHTML z nizi in brez inline-atributov (obdelovalniki samo kot funkcije; test_admin_xss.js).
// dogodki.js poklice window.novDogodek.zaUrejevalnik() po izrisu urejevalnika; brez tega modula urejevalnik dela kot prej.
(function () {
  "use strict";
  const cele = (n) => (Number.isSafeInteger(Number(n)) ? Number(n) : 0);
  const NAJVEC_SLIKA = 10 * 1024 * 1024;     // bajtov, pred pomanjsanjem
  const IZREZ_SIRINA = 1080;                 // px, najvecja sirina izreza plakata (manjsih slik ne povecujemo); canvas odstrani EXIF/GPS
  const TRAJANJE_H = 6;                      // konec novega dogodka = zacetek + 6 h (uredljivo v urejevalniku)
  const NAJVEC_TEDNOV = 12;                  // skladno s POST /admin/api/events/:id/duplicate

  // --- pomozne (enake kot v dogodki.js; tam so zasebne) ---
  // "12,50" / "12.5" / "12" -> 1250; "" -> null; sicer NaN. Brez plavajoce vejice (I9).
  function centi(niz) {
    const s = String(niz || "").trim();
    if (s === "") return null;
    const m = /^(\d{1,6})(?:[.,](\d{1,2}))?$/.exec(s);
    if (!m) return NaN;
    return Number(m[1]) * 100 + Number((m[2] || "0").padEnd(2, "0"));
  }
  function lokalno(ms) {   // ms -> vrednost za <input type=datetime-local> v lokalnem casu brskalnika
    const d = new Date(ms); if (Number.isNaN(d.getTime())) return "";
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  }
  // Samodejna objava (#327): vedno po ljubljanskem casu
  const datumLj = (iso) => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("sl-SI", { timeZone: "Europe/Ljubljana", dateStyle: "short", timeStyle: "short" }); };
  const izLokalnega = (v) => { const t = v ? new Date(v).getTime() : NaN; return Number.isNaN(t) ? null : t; };
  function polje(id, oznaka, vnos, pomoc) {
    vnos.id = id;
    return h("div", { class: "dlg-polje" }, h("label", { for: id }, oznaka), vnos, pomoc ? h("span", { class: "pomoc" }, pomoc) : null);
  }
  function naDogodek(id) {
    const n = cele(id);
    if (n <= 0) return;
    history.pushState(null, "", "#/dogodki/" + n);
    pokaziZavihek("dogodki");
  }

  // =====================================================================================================================
  // NOV DOGODEK (korak 1)
  // =====================================================================================================================
  async function klubiZaIzbiro() {
    const r = await klic("GET", "/admin/api/clubs");
    return (Array.isArray(r) ? r : []).filter((k) => Number.isSafeInteger(Number(k.id)))
      .sort((a, b) => String(a.name).localeCompare(String(b.name), "sl"));
  }
  function obrazecNov(klubi) {
    const klub = h("select", {}, h("option", { value: "" }, "— izberi klub —"),
      klubi.map((k) => h("option", { value: String(cele(k.id)) }, [k.name, k.city, k.hidden ? "skrit" : "", k.is_demo ? "demo" : ""].filter(Boolean).join(" – "))));
    const naslov = h("input", { maxlength: "200", autocomplete: "off" });
    const zacetek = h("input", { type: "datetime-local" });
    const cenaV = h("input", { inputmode: "decimal", placeholder: "prazno = brez vstopnic", autocomplete: "off" });
    const kap = h("input", { inputmode: "numeric", placeholder: "brez omejitve", autocomplete: "off" });
    const vIme = h("input", { autocomplete: "off" }), vMesto = h("input", { autocomplete: "off" });
    // Klub organizator (npr. Outly) nima lastne lokacije: server (POST /events) zahteva prizorisce, zato ga vprasamo ze v prvem koraku.
    const prizorisce = h("div", { class: "skrito" },
      polje("nd_venueName", "Prizorišče: ime", vIme, "Klub je organizator, dogodek potrebuje lokacijo."), polje("nd_venueCity", "Prizorišče: mesto", vMesto));
    klub.onchange = () => {
      const k = klubi.find((x) => String(cele(x.id)) === klub.value);
      prizorisce.classList.toggle("skrito", !(k && k.is_organizer));
    };
    const koren = h("div", {},
      polje("nd_klub", "Klub", klub), polje("nd_naslov", "Naslov", naslov), polje("nd_zacetek", "Začetek", zacetek, "Konec se nastavi samodejno čez 6 ur; popraviš ga v naslednjem koraku."),
      polje("nd_cena", "Cena vstopnice (€)", cenaV, "Prazno = brez vstopnic na Outlyju. 0 = brezplačno."), polje("nd_kap", "Kapaciteta", kap, "Prazno = brez omejitve."), prizorisce);
    // vrne { napaka } ali { telo } za POST /events
    function preberi() {
      const k = klubi.find((x) => String(cele(x.id)) === klub.value);
      if (!k) return { napaka: "Izberi klub." };
      const ime = naslov.value.trim();
      if (!ime) return { napaka: "Naslov je obvezen." };
      const t0 = izLokalnega(zacetek.value);
      if (t0 === null) return { napaka: "Začetek je obvezen." };
      if (t0 <= Date.now()) return { napaka: "Začetek mora biti v prihodnosti." };
      const cenaC = centi(cenaV.value);
      if (Number.isNaN(cenaC)) return { napaka: "Cena: vpiši znesek, npr. 12,50 (prazno = brez vstopnic na Outlyju)." };
      const kapS = kap.value.trim();
      if (kapS !== "" && !(/^\d{1,6}$/.test(kapS) && Number(kapS) >= 1 && Number(kapS) <= 100000)) return { napaka: "Kapaciteta: celo število od 1 do 100000 (prazno = brez omejitve)." };
      const telo = { clubId: cele(k.id), title: ime, startAt: new Date(t0).toISOString(), endAt: new Date(t0 + TRAJANJE_H * 3600e3).toISOString(), status: "draft" };
      if (cenaC !== null) telo.ticketPriceCents = cenaC;
      if (kapS !== "") telo.capacity = Number(kapS);
      if (k.is_organizer) {
        if (!vIme.value.trim() || !vMesto.value.trim()) return { napaka: "Klub je organizator: vpiši ime in mesto prizorišča." };
        telo.venueName = vIme.value.trim(); telo.venueCity = vMesto.value.trim();
      }
      return { telo };
    }
    return { koren, preberi };
  }
  async function novDogodek() {
    let klubi;
    try { klubi = await klubiZaIzbiro(); } catch (e) { obvesti(e.message, "slabo"); return null; }
    if (!klubi.length) { obvesti("Ni klubov: najprej ustvari klub v zavihku Klubi.", "slabo"); return null; }
    const f = obrazecNov(klubi);
    for (;;) {
      const ok = await potrdi({ naslov: "Nov dogodek", potrdiBesedilo: "Ustvari osnutek",
        vsebina: [h("p", {}, "Najprej osnutek s petimi podatki. Plakat, opis, žanre in okno prodaje dopolniš v naslednjem koraku; osnutek ni viden v aplikaciji, dokler ga ne objaviš."), f.koren] });
      if (!ok) return null;
      const v = f.preberi();
      if (v.napaka) { obvesti(v.napaka, "slabo"); continue; }   // okno se ponovno odpre z vpisanimi vrednostmi
      try {
        const e = await klic("POST", "/admin/api/events", v.telo);   // admin pot: deluje za vsak klub, tudi ce je admin sam lastnik drugega kluba; vedno osnutek
        obvesti(`Osnutek »${e.title}« je ustvarjen. Dopolni ga in objavi.`, "ok");
        naDogodek(e.id);
        return e;
      } catch (err) { obvesti(err.message, "slabo"); }
    }
  }

  // =====================================================================================================================
  // NALAGANJE PLAKATA (korak 2)
  // =====================================================================================================================
  // Pogodba z backendom (enako kot spletna aplikacija, webapp/js/api.js): VSAKO polje podpisa razen NEPODPISANA gre Cloudinaryju nespremenjeno (camelCase -> snake_case).
  const NEPODPISANA = new Set(["signature", "apiKey", "api_key", "cloudName", "cloud_name", "resourceType", "resource_type"]);
  const vSnake = (k) => k.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
  function parametriPodpisa(p) {
    const out = {};
    for (const [k, v] of Object.entries(p || {})) {
      if (NEPODPISANA.has(k) || v === undefined || v === null) continue;
      out[vSnake(k)] = Array.isArray(v) ? v.join(",") : String(v);
    }
    return out;
  }
  // Plakata sta dva (outly-backend#400): velik 4:5 (poster_url) in majhen 3:4 (poster_card_url). Slika se NE naloži takoj: najprej izrez s fiksnim razmerjem.
  const OKVIRJI = [
    { w: 4, h: 5, oznaka: "Plakat – velik (4:5)", vnos: "dge_poster", kje: "dge_plakat_orodja", pred: "dge_plakat" },
    { w: 3, h: 4, oznaka: "Plakat – majhen (3:4)", vnos: "dge_poster_card", kje: "dge_plakat_kartica_orodja", pred: "dge_plakat_kartica" },
  ];
  async function preberiSliko(datoteka) {
    if (!datoteka || !/^image\//.test(datoteka.type || "")) throw new Error("Izberi sliko (JPEG, PNG ali WebP).");
    if (datoteka.size > NAJVEC_SLIKA) throw new Error("Slika je prevelika (največ 10 MB).");
    const bitmap = await createImageBitmap(datoteka).catch(() => null);
    if (!bitmap) throw new Error("Slike ni mogoče prebrati. Izberi JPEG, PNG ali WebP.");
    return bitmap;
  }
  // Urejevalnik izreza v potrditvenem oknu: okvir ima razmerje koncne slike (premik s povleci-in-spusti ali s puscicami, povecava z drsnikom ali +/-), zraven pomanjsan predogled.
  // Vrne Blob (JPEG, tocno w:h, sirina najvec IZREZ_SIRINA, brez povecevanja) ali null (Preklici: nic se ne naloži). Canvas ne ohrani EXIF/GPS.
  async function izrezi(bitmap, okvir) {
    const pw = 240, ph = Math.round(pw * okvir.h / okvir.w);
    const pokrij = Math.max(pw / bitmap.width, ph / bitmap.height);   // najmanjsa skala, pri kateri slika zapolni cel okvir (brez praznih robov)
    let povecava = 1, ox = (pw - bitmap.width * pokrij) / 2, oy = (ph - bitmap.height * pokrij) / 2;
    const skala = () => pokrij * povecava;
    const platno = h("canvas", { width: String(pw), height: String(ph), class: "dg-izrez", tabindex: "0", role: "img", "aria-label": `Izrez ${okvir.w}:${okvir.h}: povleci sliko, puščice premikajo, + in − povečujeta` });
    const mali = h("canvas", { width: "96", height: String(Math.round(96 * okvir.h / okvir.w)), class: "dg-izrez-mali", "aria-hidden": "true" });
    const drsnik = h("input", { type: "range", min: "100", max: "400", step: "1", value: "100", "aria-label": "Povečava" });
    const omeji = () => {
      const s = skala();
      ox = Math.min(0, Math.max(pw - bitmap.width * s, ox)); oy = Math.min(0, Math.max(ph - bitmap.height * s, oy));
    };
    const narisi = (c) => {
      const g = c.getContext("2d"), f = c.width / pw, s = skala();
      g.fillStyle = "#ffffff"; g.fillRect(0, 0, c.width, c.height);
      g.drawImage(bitmap, ox * f, oy * f, bitmap.width * s * f, bitmap.height * s * f);
    };
    const osvezi = () => { omeji(); narisi(platno); narisi(mali); };
    const povecaj = (nova) => {   // sredina okvirja ostane na isti tocki slike
      const s0 = skala(), cx = (pw / 2 - ox) / s0, cy = (ph / 2 - oy) / s0;
      povecava = Math.min(4, Math.max(1, nova)); drsnik.value = String(Math.round(povecava * 100));
      const s1 = skala(); ox = pw / 2 - cx * s1; oy = ph / 2 - cy * s1;
      osvezi();
    };
    drsnik.oninput = () => povecaj(Number(drsnik.value) / 100);
    let vlek = null;
    platno.onpointerdown = (e) => { vlek = { x: e.clientX, y: e.clientY, ox, oy }; if (platno.setPointerCapture) try { platno.setPointerCapture(e.pointerId); } catch (_) {} };
    platno.onpointermove = (e) => {
      if (!vlek) return;
      const r = platno.getBoundingClientRect(), k = pw / (r.width || pw);
      ox = vlek.ox + (e.clientX - vlek.x) * k; oy = vlek.oy + (e.clientY - vlek.y) * k; osvezi();
    };
    platno.onpointerup = platno.onpointercancel = () => { vlek = null; };
    platno.onkeydown = (e) => {
      const korak = { ArrowLeft: [8, 0], ArrowRight: [-8, 0], ArrowUp: [0, 8], ArrowDown: [0, -8] }[e.key];
      if (korak) { e.preventDefault(); ox += korak[0]; oy += korak[1]; osvezi(); }
      else if (e.key === "+" || e.key === "=") { e.preventDefault(); povecaj(povecava + 0.1); }
      else if (e.key === "-") { e.preventDefault(); povecaj(povecava - 0.1); }
    };
    osvezi();
    const izid = await potrdi({ naslov: `${okvir.oznaka}: izrez`, potrdiBesedilo: "Uporabi",
      vsebina: [h("p", {}, `Povleci sliko na pravo mesto in jo po potrebi povečaj. Izrez ima razmerje ${okvir.w}:${okvir.h} in zapolni cel okvir. Slika se naloži šele, ko klikneš »Uporabi«.`),
        h("div", { class: "dg-izrez-vrsta" }, platno, h("div", {}, h("span", { class: "pomoc" }, "Predogled v pravem razmerju"), mali)),
        h("label", {}, "Povečava", drsnik)] });
    if (!izid) return null;
    const s = skala(), sx = Math.max(0, -ox / s), sy = Math.max(0, -oy / s), sw = pw / s, sh = ph / s;
    let izW = Math.floor(Math.min(IZREZ_SIRINA, sw) / okvir.w) * okvir.w;   // večkratnik w: višina je tocno w:h
    if (izW < okvir.w) izW = okvir.w;
    const izH = izW / okvir.w * okvir.h;
    const c = document.createElement("canvas");
    c.width = izW; c.height = izH;
    const g = c.getContext("2d");
    g.fillStyle = "#ffffff"; g.fillRect(0, 0, izW, izH);   // prosojen PNG -> JPEG brez crnega ozadja
    g.drawImage(bitmap, sx, sy, sw, sh, 0, 0, izW, izH);
    const blob = await new Promise((res) => { try { c.toBlob(res, "image/jpeg", 0.88); } catch (_) { res(null); } });
    if (!blob) throw new Error("Slike ni mogoče pripraviti za nalaganje. Izberi JPEG, PNG ali WebP.");
    return blob;
  }
  // -> https URL slike na Cloudinaryju (blob: ze izrezan JPEG)
  async function naloziBlob(blob) {
    const p = await klic("POST", "/uploads/cloudinary-signature");
    if (!p || !p.signature || !p.apiKey || !p.cloudName) throw new Error("Nalaganje slike ni na voljo (strežnik ni vrnil podpisa).");
    const f = new FormData();
    f.append("api_key", p.apiKey);
    for (const [k, v] of Object.entries(parametriPodpisa(p))) f.append(k, v);
    f.append("signature", p.signature);
    f.append("file", blob, "plakat.jpg");
    let odg;
    try { odg = await fetch(`https://api.cloudinary.com/v1_1/${encodeURIComponent(p.cloudName)}/image/upload`, { method: "POST", body: f }); }
    catch (_) { throw new Error("Nalaganje slike ni uspelo: ni povezave."); }
    const r = await odg.json().catch(() => ({}));
    if (!odg.ok || typeof r.secure_url !== "string" || !/^https:\/\//.test(r.secure_url)) throw new Error(`Nalaganje slike ni uspelo (${cele(odg.status) || "napaka"}).`);
    return r.secure_url;
  }
  function orodjaPlakata() { for (const okvir of OKVIRJI) orodjeZaPolje(okvir); }
  function orodjeZaPolje(okvir) {
    const kje = $(okvir.kje);
    if (!kje) return;
    const izbira = h("input", { type: "file", accept: "image/*", class: "skrito", id: okvir.pred + "_datoteka", "aria-label": "Izberi sliko: " + okvir.oznaka });
    const gumb = h("button", { type: "button", class: "tih mali", id: okvir.pred + "_nalozi" }, "Naloži sliko");
    gumb.onclick = () => izbira.click();
    izbira.onchange = async () => {
      const d = izbira.files && izbira.files[0];
      izbira.value = "";
      if (!d) return;
      gumb.disabled = true;
      let bitmap = null;
      try {
        bitmap = await preberiSliko(d);
        const blob = await izrezi(bitmap, okvir);
        if (!blob) return;   // Preklici: nic se ne naloži
        gumb.textContent = "Nalagam …";
        const url = await naloziBlob(blob);
        const vnos = $(okvir.vnos);
        if (vnos) { vnos.value = url; if (typeof vnos.oninput === "function") vnos.oninput(); }
        obvesti("Slika je naložena. Shrani spremembe, da se plakat zapiše.", "ok");
      } catch (e) { obvesti(e.message, "slabo"); }
      finally { if (bitmap && bitmap.close) bitmap.close(); gumb.disabled = false; gumb.textContent = "Naloži sliko"; }
    };
    kje.replaceChildren(gumb, izbira, h("span", { class: "pomoc" }, `Po izbiri slike odpreš izrez ${okvir.w}:${okvir.h}; naloži se šele po »Uporabi« (do 10 MB, največ 1080 px v širino). URL se vpiše v polje zgoraj.`));
  }

  // =====================================================================================================================
  // PRED OBJAVO (korak 3)
  // =====================================================================================================================
  // Besedila so napisana za osnutek (kaj bi veljalo ob objavi); neznana vrsta pokaze besedilo streznika.
  const BESEDILA = {
    prodajalec_nepopoln: "Podatki prodajalca kluba niso popolni: nakup vstopnic bi bil zavrnjen. Dopolni jih v zavihku Klubi.",
    placila_niso_pripravljena: "Klub nima dokončanega prejemanja plačil ali plačila v sistemu niso nastavljena: plačljiv nakup bi bil zavrnjen.",
    brez_plakata: "Brez plakata, začetek je v manj kot 14 dneh.",
    brez_cene: "Brez cene vstopnice in brez zunanje prodaje: na Outlyju ne bo vstopnic.",
    brez_kapacitete: "Plačljiv dogodek brez kapacitete: prodaja je neomejena.",
    brez_konca: "Brez konca: sken vstopnic na vratih naslednji dan ne bo veljal.",
    demo_objavljen: "Klub je demo: dogodek bo viden v aplikaciji, nakup bo zavrnjen.",
    prodaja_ustavljena: "Prodaja je ustavljena: ob objavi kupci ne bodo mogli kupiti.",
  };
  const PIKE = { rdece: "slabo", oranzno: "opoz", rumeno: "rumena" };
  let preveri = { id: null, stanje: "ni" };   // stanje: ni (ni osnutek) | caka | ok | rdece | napaka
  let podvojeni = null;                       // { iz, events } zadnji seznam podvojenih osnutkov (prikazan v urejevalniku izvora)

  function narisiRazsiritve() {
    const kje = $("dge_razsiritve");
    if (!kje) return;
    const deli = [];
    if (preveri.stanje !== "ni") deli.push(blokPreveri());
    if (podvojeni && podvojeni.iz === preveri.id) deli.push(blokPodvojeni(podvojeni));
    kje.replaceChildren(...deli);
    const objavi = $("dge_objavi");
    if (objavi && preveri.stanje !== "ni") {
      objavi.disabled = preveri.stanje !== "ok";
      if (preveri.stanje === "ok") objavi.removeAttribute("title");
      else objavi.setAttribute("title", preveri.stanje === "caka" ? "Preverjam …" : preveri.stanje === "napaka" ? "Pregleda ni bilo mogoče opraviti." : "Najprej odpravi rdeče ovire.");
    }
  }
  function vrsticaPreveri(o) {
    const resnost = ["rdece", "oranzno", "rumeno"].includes(o.resnost) ? o.resnost : "rumeno";
    return h("div", { class: "op-vrstica brez-cilja pr-vrstica" },
      h("span", { class: "op-pika " + PIKE[resnost], "aria-hidden": "true" }),
      h("span", { class: "op-besedilo" },
        h("b", {}, resnost === "rdece" ? "Ovira: " : "Opozorilo: "), BESEDILA[o.vrsta] || String(o.besedilo || o.vrsta || "")));
  }
  function blokPreveri() {
    const p = preveri;
    const gumb = h("button", { type: "button", class: "tih mali", id: "dge_preveri_znova" }, "Preveri znova");
    gumb.onclick = () => naloziPreveri(p.id);
    if (p.stanje === "caka") gumb.disabled = true;   // med preverjanjem ne zaganjaj novega
    const telo = [];
    if (p.stanje === "caka") telo.push(h("div", { class: "prazno" }, "Preverjam …"));
    else if (p.stanje === "napaka") telo.push(h("div", { class: "opozorilo" }, "Pregleda ni bilo mogoče opraviti (" + p.napaka + "). Objava je onemogočena, dokler pregled ne uspe."));
    else {
      const rdeca = p.items.filter((o) => o.resnost === "rdece");
      if (!p.items.length) telo.push(h("div", { class: "op-seznam" }, h("div", { class: "op-vrstica brez-cilja pr-vrstica" }, h("span", { class: "op-pika ok", "aria-hidden": "true" }),
        h("span", { class: "op-besedilo" }, h("b", {}, "Vse je v redu: "), "ni ovir in opozoril. Dogodek lahko objaviš."))));
      else telo.push(h("div", { class: "op-seznam" }, p.items.map(vrsticaPreveri)));
      if (rdeca.length) telo.push(h("p", { class: "pr-opomba" }, "Gumb »Objavi« je onemogočen, dokler obstaja rdeča ovira. Oranžna in rumena opozorila objave ne ustavijo."));
      else if (p.items.length) telo.push(h("p", { class: "pr-opomba" }, "Opozorila objave ne ustavijo."));
      telo.push(h("p", { class: "pr-opomba" }, "Pregled velja za shranjene podatke; neshranjenih sprememb ne vidi."));
    }
    const nacrtovan = trenutniDogodek;
    if (nacrtovan && nacrtovan.publish_at && cele(nacrtovan.id) === p.id) {
      telo.push(h("p", { class: "pr-opomba", id: "dge_objava_nacrt" }, `Samodejna objava ob ${datumLj(nacrtovan.publish_at)} (ljubljanski čas): ob tem času se opravi ta isti pregled. Rdeča ovira ali začetek dogodka pred tem časom pustita dogodek kot osnutek in sprožita rdeče opozorilo.`));
    }
    if (p.stanje === "rdece" || p.stanje === "napaka") {   // izredna pot: objava kljub oviri, z vpisom in razlogom (dnevnik)
      const vseeno = h("button", { type: "button", class: "nevarno mali", id: "dge_objavi_vseeno" }, "Objavi vseeno");
      vseeno.onclick = () => objaviVseeno(p.id);
      telo.push(h("div", { class: "vrsta", style: "margin-top:8px" }, vseeno));
    }
    return h("div", { class: "skupina", id: "dge_preveri" }, h("h2", {}, "Pred objavo", h("span", { class: "desno" }, gumb)), h("div", { class: "telo" }, telo));
  }
  async function naloziPreveri(id) {
    preveri = { id, stanje: "caka", items: [] };
    narisiRazsiritve();
    let odg, napaka = null;
    try { odg = await klic("GET", "/admin/api/opozorila?dogodek=" + encodeURIComponent(String(id))); }
    catch (e) { napaka = e; }
    if (preveri.id !== id) return;   // urejevalnik je medtem pokazal drug dogodek
    if (napaka || !odg || !Array.isArray(odg.items)) {
      preveri = { id, stanje: "napaka", items: [], napaka: napaka ? String(napaka.message || napaka).slice(0, 120) : "neveljaven odgovor" };
    } else {
      const items = odg.items;
      preveri = { id, stanje: items.some((o) => o.resnost === "rdece") ? "rdece" : "ok", items };
    }
    narisiRazsiritve();
  }
  let osveziUrejevalnik = null;   // dogodki.js: ponovno nalozi urejevalnik
  async function objaviVseeno(id) {
    const e = trenutniDogodek;
    if (!e || cele(e.id) !== id) return;
    const ok = await potrdi({ naslov: "Objavim kljub oviri?", nevarno: true, potrdiBesedilo: "Objavi vseeno", vpis: "OBJAVI", razlog: "obvezen",
      vsebina: [h("p", {}, `»${e.title}« bo viden v aplikaciji, čeprav pregled pred objavo ni čist (rdeča ovira ali pregled ni uspel). Nakup bo morda zavrnjen. Sledilci kluba dobijo obvestilo.`),
        e.status === "cancelled" ? h("p", {}, "Dogodek je bil odpovedan; kupci so morda že dobili vračila. Ponovna objava obvesti sledilce.") : null,
        h("p", {}, "Razlog se zapiše v dnevnik dejanj.")] });
    if (!ok) return;
    try {
      await klic("PATCH", "/admin/api/events/" + id, { status: "published", reason: ok.razlog });
      obvesti(`»${e.title}« objavljen kljub oviri.`, "ok");
      if (osveziUrejevalnik) await osveziUrejevalnik(); else naDogodek(id);
    } catch (err) { obvesti(err.message, "slabo"); }
  }
  let trenutniDogodek = null;
  // true: Objavi mora ostati onemogocen (osnutek, katerega pregled se ni koncal ali ima rdeco oviro)
  function objavaBlokirana(id) {
    return preveri.id === id && preveri.stanje !== "ni" && preveri.stanje !== "ok";
  }

  // =====================================================================================================================
  // PODVOJI (korak 4)
  // =====================================================================================================================
  function blokPodvojeni(p) {
    return h("div", { class: "skupina", id: "dge_podvojeni" }, h("h2", {}, `Ustvarjeni osnutki (${p.events.length})`),
      h("div", { class: "telo" },
        h("div", { class: "op-seznam" }, p.events.map((e) => {
          const a = h("a", { class: "op-vrstica pr-vrstica", href: "#/dogodki/" + cele(e.id) },
            h("span", { class: "op-pika opoz", "aria-hidden": "true" }), h("span", { class: "op-besedilo" }, `${datum(e.start_at)} – ${e.title} (osnutek #${cele(e.id)})`));
          a.onclick = (ev) => { if (ev && ev.preventDefault) ev.preventDefault(); naDogodek(e.id); };
          return a;
        })),
        h("p", { class: "pr-opomba" }, "Osnutki niso objavljeni. Odpri vsakega, preveri in objavi.")));
  }
  function privzetiZacetek(startAt) {   // izvorni zacetek + 7 dni; ce je ze mimo, prvi tedenski termin v prihodnosti
    const teden = (ms) => { const d = new Date(ms); d.setDate(d.getDate() + 7); return d.getTime(); };   // 7 KOLEDARSKIH dni v lokalnem casu (ura ostane cez prehod casa)
    let t = new Date(startAt).getTime();
    if (Number.isNaN(t)) t = Date.now();
    t = teden(t);
    while (t <= Date.now() + 36e5) t = teden(t);
    return t;
  }
  async function podvoji(e) {
    const zacetek = h("input", { type: "datetime-local" }); zacetek.value = lokalno(privzetiZacetek(e.start_at));
    const dodatni = h("select", {}, Array.from({ length: NAJVEC_TEDNOV }, (_, i) => h("option", { value: String(i) }, i === 0 ? "0 (samo en dogodek)" : String(i))));
    const povzetek = h("p", { class: "pr-opomba" });
    const osvezi = () => { povzetek.textContent = `Število novih osnutkov: ${1 + Number(dodatni.value)}.`; };
    dodatni.onchange = osvezi; osvezi();
    const koren = h("div", {}, polje("pv_zacetek", "Nov začetek", zacetek, "Konec in okno prodaje se premakneta za enak zamik."),
      polje("pv_dodatni", "Ponavljaj vsak teden, dodatnih", dodatni, "Največ 11 dodatnih tednov (skupaj 12 osnutkov)."), povzetek);
    for (;;) {
      const ok = await potrdi({ naslov: "Podvojim dogodek?", potrdiBesedilo: "Podvoji",
        vsebina: [h("p", {}, `»${e.title}« se kopira v osnutek: naslov, opis, plakat, žanri, starost, cena, kapaciteta in prizorišče.`),
          h("p", {}, "Ne kopirajo se prodane vstopnice, pavza prodaje, posnetek po dogodku in VIP razpored miz (tega nastaviš pri vsakem posebej)."), koren] });
      if (!ok) return null;
      const t0 = izLokalnega(zacetek.value);
      if (t0 === null) { obvesti("Nov začetek je obvezen.", "slabo"); continue; }
      if (t0 <= Date.now()) { obvesti("Nov začetek mora biti v prihodnosti.", "slabo"); continue; }
      const dod = Number(dodatni.value);
      const telo = { startAt: new Date(t0).toISOString() };
      if (dod > 0) { telo.ponovi = "weekly"; telo.n = dod + 1; }
      try {
        const r = await klic("POST", "/admin/api/events/" + cele(e.id) + "/duplicate", telo);
        const nove = Array.isArray(r && r.events) ? r.events : [];
        obvesti(nove.length === 1 ? "Osnutek je ustvarjen." : `Ustvarjenih osnutkov: ${nove.length}.`, "ok");
        podvojeni = { iz: cele(e.id), events: nove };
        narisiRazsiritve();
        return nove;
      } catch (err) { obvesti(err.message, "slabo"); }
    }
  }

  // =====================================================================================================================
  // KLIC IZ dogodki.js
  // =====================================================================================================================
  function zaUrejevalnik(ctx) {
    const e = (ctx && ctx.event) || {};
    const id = cele(e.id);
    if (id <= 0) return;
    trenutniDogodek = e; osveziUrejevalnik = ctx.osvezi || null;
    orodjaPlakata();
    const kje = $("dge_gumbi");
    if (kje) {
      const g = h("button", { type: "button", class: "tih mali", id: "dge_podvoji" }, "Podvoji");
      g.onclick = () => podvoji(e);
      kje.append(g);
    }
    if (e.status !== "published") { preveri = { id, stanje: "caka", items: [] }; narisiRazsiritve(); naloziPreveri(id); }
    else { preveri = { id, stanje: "ni", items: [] }; narisiRazsiritve(); }
  }
  function vstaviGumb() {
    const osvezi = $("dg_osvezi");
    if (!osvezi || !osvezi.parentNode || $("dg_nov")) return;
    const g = h("button", { type: "button", id: "dg_nov", class: "mali" }, "Nov dogodek");
    g.onclick = () => { novDogodek(); };
    osvezi.parentNode.insertBefore(g, osvezi);
  }
  window.novDogodek = { zaUrejevalnik, objavaBlokirana, vstaviGumb, novDogodek, podvoji, naloziBlob, izrezi, parametriPodpisa };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", vstaviGumb); else vstaviGumb();
})();
