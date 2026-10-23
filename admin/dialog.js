// Potrditveno okno panela (faza 1, 21. 10. 2026): namesto window.confirm, ki ga brskalniska orodja (in nekateri mobilni brskalniki) blokirajo.
// Brez ogrodja; DOM samo prek h() (textContent), nikoli HTML iz podatkov (XSS, glej STATE »Admin panel«).
// potrdi({ naslov, vsebina, potrdiBesedilo, nevarno, vpis, razlog }) -> Promise<null | { razlog }>
//   vsebina   niz ali seznam vozlisc/nizov (h(...)); nizi gredo v DOM kot besedilo
//   vpis      neobvezno: beseda, ki jo mora admin vpisati (npr. "ODPOVEJ"), sicer gumb ostane onemogocen
//   razlog    "obvezen" | "neobvezen" | undefined: polje za razlog (gre v dnevnik admin dejanj)
// Esc / klik na ozadje / »Prekliči« = null.
(function () {
  "use strict";
  function el(tag, lastnosti, ...otroci) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(lastnosti || {})) {
      if (k === "class") e.className = v; else if (k.startsWith("on")) e[k] = v; else e.setAttribute(k, v);
    }
    for (const o of otroci.flat()) if (o !== null && o !== undefined && o !== false) e.append(o.nodeType ? o : document.createTextNode(String(o)));
    return e;
  }
  let odprt = null;
  function potrdi(o) {
    if (odprt) odprt(null);
    return new Promise((koncaj) => {
      const prej = document.activeElement;
      const id = "dlg" + Math.random().toString(36).slice(2, 8);
      const vpisEmail = !!o.vpis && String(o.vpis).includes("@");   // e-naslov: tipkovnica za e-naslove, brez samodejnih velikih crk
      const vpisPolje = o.vpis ? el("input", { id: id + "v", autocomplete: "off", spellcheck: "false", ...(vpisEmail ? { inputmode: "email", autocapitalize: "off" } : { autocapitalize: "characters" }) }) : null;
      const razlogPolje = o.razlog ? el("textarea", { id: id + "r", maxlength: "500", rows: "2" }) : null;
      const gumbOk = el("button", { type: "button", class: o.nevarno ? "nevarno-polno" : "" }, o.potrdiBesedilo || "Potrdi");
      const gumbNe = el("button", { type: "button", class: "tih" }, "Prekliči");
      const veljavno = () => (!vpisPolje || vpisPolje.value.trim().toUpperCase() === String(o.vpis).toUpperCase())
        && (o.razlog !== "obvezen" || (razlogPolje && razlogPolje.value.trim().length >= 3));
      const osvezi = () => { gumbOk.disabled = !veljavno(); };
      const okno = el("div", { class: "dlg-okno" + (o.nevarno ? " nevarno" : ""), role: "dialog", "aria-modal": "true", "aria-labelledby": id + "n", "aria-describedby": id + "b" },
        el("h3", { id: id + "n" }, o.naslov || "Potrdi"),
        el("div", { id: id + "b", class: "dlg-besedilo" }, o.vsebina || ""),
        razlogPolje ? el("div", { class: "dlg-polje" }, el("label", { for: id + "r" }, o.razlog === "obvezen" ? "Razlog (obvezen, gre v dnevnik)" : "Razlog (neobvezno, gre v dnevnik)"), razlogPolje) : null,
        vpisPolje ? el("div", { class: "dlg-polje" }, el("label", { for: id + "v" }, `Za potrditev vpiši ${o.vpis}`), vpisPolje) : null,
        el("div", { class: "dlg-gumbi" }, gumbNe, gumbOk));
      const ozadje = el("div", { class: "dlg-ozadje" }, okno);
      const zapri = (izid) => {
        if (!ozadje.isConnected) return;
        ozadje.remove(); document.removeEventListener("keydown", tipka, true); document.body.classList.remove("dlg-odprt");
        odprt = null;
        if (prej && prej.focus) try { prej.focus(); } catch (_) {}
        koncaj(izid);
      };
      const tipka = (e) => {
        if (e.key === "Escape") { e.preventDefault(); zapri(null); }
        else if (e.key === "Tab") {   // zarisce ostane v oknu
          const f = [...okno.querySelectorAll("input,textarea,button:not([disabled])")];
          if (!f.length) return;
          const i = f.indexOf(document.activeElement);
          if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); }
          else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); }
        }
      };
      gumbNe.onclick = () => zapri(null);
      gumbOk.onclick = () => { if (veljavno()) zapri({ razlog: razlogPolje ? razlogPolje.value.trim() : "" }); };
      ozadje.onclick = (e) => { if (e.target === ozadje) zapri(null); };
      if (vpisPolje) vpisPolje.oninput = osvezi;
      if (razlogPolje) razlogPolje.oninput = osvezi;
      osvezi();
      document.addEventListener("keydown", tipka, true);
      document.body.classList.add("dlg-odprt");
      document.body.appendChild(ozadje);
      odprt = zapri;
      (vpisPolje || razlogPolje || gumbNe).focus();
    });
  }
  window.potrdi = potrdi;
})();
