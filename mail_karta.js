"use strict";
/**
 * Mail z vstopnico v obliki prave karte (Martin, 24. 10. 2026, DECISIONS): levi stolpec logotip Outly, koda QR in podatki pod njo, srednji podatki
 * dogodka, desni plakat; vodoravno na racunalniku IN na telefonu (Martinova odlocitev, stolpci v odstotkih). Temno ozadje kot aplikacija, karta bela,
 * koda QR na beli podlagi (sken na vratih). Velja za potrdilo kupcu z racunom (I32), mail z vstopnicami gostu (I22) in prenos gostu (I23).
 *
 * Samo izris HTML (besedilo text/plain in pravna vsebina se tu NE spreminjata). Pravila:
 *   - postavitev s tabelami in vrsticnimi slogi (Outlook, Gmail); brez flex/grid, brez skriptov, brez zunanjih slik in pisav (sledenje: samo cid:);
 *   - vse slike so vgrajene priloge (CID): koda QR (ticket-qr-N), logotip (outly-logo), plakat (event-poster);
 *   - vsak podatek iz baze gre skozi `ubezi` (I43);
 *   - drobni tisk >= 13 px in noga s firmo 12 px: kontrast na crni >= kontrast #555 na beli (7,5 : 1): #A1A1A6 na #000000 je 8,2 : 1;
 *   - plakat: prenese ga streznik (ne prejemnikov odjemalec), samo z NASEGA Cloudinaryja (SSRF), z rokom, omejeno velikostjo in predpomnilnikom
 *     in zdruzevanjem hkratnih klicev (ob navali nakupov za isti dogodek en prenos); ob kakrsnikoli napaki mail gre brez plakata (srednji stolpec se razsiri).
 */
const fs = require("fs");
const path = require("path");

const ubezi = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const PISAVA = "Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const B = {   // barve
  ozadje: "#000000", besedilo: "#FFFFFF", svetlo: "#D1D1D6", drobno: "#A1A1A6", noga: "#A1A1A6", crta: "#2C2C30", oznaka: "#8FA8FF",
  gumb: "#4C76FF", karta: "#FFFFFF", krtica: "#F4F4F6", karta_besedilo: "#111111", karta_sivo: "#555555", perforacija: "#D0D0D6", modra_temna: "#3358E0", plakat_ozadje: "#141416",
};
const SLOG_DROBNO = `margin:20px 0 0;font-size:13px;line-height:1.5;color:${B.drobno}`;

// --- priloge (CID) ---
const CID_LOGO = "outly-logo", CID_PLAKAT = "event-poster";
const LOGO_B64 = fs.readFileSync(path.join(__dirname, "slike", "outly-logo.png")).toString("base64");
const prilogaLogo = () => ({ filename: "outly.png", content: LOGO_B64, content_type: "image/png", content_id: CID_LOGO });
const prilogaPlakat = (buf) => ({ filename: "event.jpg", content: buf.toString("base64"), content_type: "image/jpeg", content_id: CID_PLAKAT });

// --- plakat ---
const PLAKAT_ROK_MS = 3000, PLAKAT_NAJVEC_B = 400 * 1024, PLAKAT_PREDPOMNILNIK = 50, PLAKAT_OK_MS = 6 * 3600 * 1000, PLAKAT_NAPAKA_MS = 60 * 1000;
const plakati = new Map();   // url -> { buf | null, do }
const plakatiVTeku = new Map();   // url -> Promise: hkratni klici za isti plakat (naval nakupov) cakajo na en prenos
// Iz shranjenega URL-ja naredi URL za mail (ozek pokoncni izrez 1 : 2, JPEG, ~30-60 KB) ali null, ce ni z nasega Cloudinaryja.
// `%` je prepovedan: fetch normalizira `%2e%2e` v `..` (pregled 24. 10.: .../upload/v1/%2e%2e/.../tujracun/image/fetch/... bi sel na tuj racun).
// Za vsak primer se preveri se normaliziran URL (kot ga poslje fetch): isti gostitelj, pot se zacne z nasim racunom in izrezom.
function plakatUrlZaMail(url, cloudName = process.env.CLOUDINARY_CLOUD_NAME) {
  if (!cloudName || !/^[A-Za-z0-9_-]+$/.test(cloudName) || typeof url !== "string" || url.length > 500) return null;
  const predpona = `https://res.cloudinary.com/${cloudName}/image/upload/`;
  if (!url.startsWith(predpona)) return null;
  const ostanek = url.slice(predpona.length);
  if (!ostanek || !/^[A-Za-z0-9_\-.,/]+$/.test(ostanek) || /\.\.|\/\.\/|^\.?\/|\/\//.test(ostanek)) return null;
  const izrez = `${predpona}c_fill,g_auto,w_300,h_600,f_jpg,q_70/`;
  const u = izrez + ostanek;
  let n;
  try { n = new URL(u); } catch (e) { return null; }
  if (n.origin !== "https://res.cloudinary.com" || n.username || n.password || n.search || n.hash || n.href !== u || !n.href.startsWith(izrez)) return null;
  return u;
}
async function plakatZaMail(url) {
  const u = plakatUrlZaMail(url);
  if (!u) return null;
  const v = plakati.get(u);
  if (v && v.do > Date.now()) return v.buf;
  if (plakatiVTeku.has(u)) return plakatiVTeku.get(u);
  const p = prenesiPlakat(u).finally(() => plakatiVTeku.delete(u));
  plakatiVTeku.set(u, p);
  return p;
}
async function prenesiPlakat(u) {
  let buf = null;
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), PLAKAT_ROK_MS);
  try {
    const r = await fetch(u, { redirect: "error", signal: ac.signal });
    const tip = r.headers.get("content-type") || "";
    if (r.ok && /^image\/jpe?g/i.test(tip) && Number(r.headers.get("content-length") || 0) <= PLAKAT_NAJVEC_B) {
      const b = Buffer.from(await r.arrayBuffer());
      if (b.length > 0 && b.length <= PLAKAT_NAJVEC_B && b[0] === 0xFF && b[1] === 0xD8) buf = b;
    }
  } catch (e) { buf = null; }
  finally { clearTimeout(t); }
  if (plakati.size >= PLAKAT_PREDPOMNILNIK) plakati.delete(plakati.keys().next().value);
  plakati.set(u, { buf, do: Date.now() + (buf ? PLAKAT_OK_MS : PLAKAT_NAPAKA_MS) });
  return buf;
}

// --- datum na karti ---
const KRATKO = {
  sl: new Intl.DateTimeFormat("sl-SI", { weekday: "short", day: "numeric", month: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "Europe/Ljubljana" }),
  en: new Intl.DateTimeFormat("en-GB", { weekday: "short", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "Europe/Ljubljana" }),
};
function datumKarta(d, jez) {
  const p = Object.fromEntries(KRATKO[jez === "sl" ? "sl" : "en"].formatToParts(new Date(d)).map((x) => [x.type, x.value]));
  const dan = String(p.weekday || "").replace(/\.$/, "");
  return jez === "sl" ? `${dan}, ${p.day}. ${p.month}. ${p.year} · ${p.hour}:${p.minute}` : `${dan}, ${p.day} ${p.month} ${p.year} · ${p.hour}:${p.minute}`;
}

// --- karta ---
// k = { jez, vrsta, naslov, vrstice: [[oznaka, vrednost, krepko?]], qr: { cid, alt, oznaka } | null, brezQr, pod: [nizi], plakat: bool }
function karta(k) {
  const N = ubezi;
  const sredina = k.plakat ? 42 : 66;
  const perforacija = `2px dashed ${B.perforacija}`;
  const logo = `<table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center"><tr>`
    + `<td style="padding:0 6px 0 0;vertical-align:middle"><img src="cid:${CID_LOGO}" width="22" height="22" alt="Outly" style="display:block;width:22px;height:22px;border:0;border-radius:6px"></td>`
    + `<td style="vertical-align:middle;font-family:${PISAVA};font-size:15px;font-weight:800;color:${B.karta_besedilo}">Outly</td></tr></table>`;
  const qr = k.qr
    ? `<img src="cid:${k.qr.cid}" class="k-qr" width="150" alt="${N(k.qr.alt)}" style="display:block;margin:12px auto 0;width:100%;max-width:150px;height:auto;border:0">`
      + (k.qr.oznaka ? `<p style="margin:8px 0 0;font-size:12px;line-height:1.35;font-weight:700;color:${B.karta_besedilo}">${N(k.qr.oznaka)}</p>` : "")
    : `<p style="margin:14px 0 0;font-size:12px;line-height:1.4;font-weight:600;color:${B.karta_besedilo}">${N(k.brezQr || "")}</p>`;
  const pod = (k.pod || []).filter(Boolean).map((v) => N(v)).join("<br>");
  const levo = `<td class="k-levo" width="34%" valign="top" bgcolor="${B.krtica}" style="width:34%;background:${B.krtica};padding:16px 10px;text-align:center;border-right:${perforacija};border-radius:14px 0 0 14px">`
    + logo + qr + (pod ? `<p class="k-mali" style="margin:6px 0 0;font-size:11px;line-height:1.4;color:#444444">${pod}</p>` : "") + `</td>`;
  const vrstice = k.vrstice.filter((v) => v && v[1]).map(([o, v, krepko]) =>
    `<p class="k-oznaka" style="margin:10px 0 0;font-size:10px;line-height:1.3;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;color:${B.karta_sivo}">${N(o)}</p>`
    + `<p class="k-vrednost" style="margin:2px 0 0;font-size:13px;line-height:1.35;font-weight:${krepko ? 700 : 600};color:${B.karta_besedilo}">${N(v)}</p>`).join("");
  const desniRob = k.plakat ? `border-right:${perforacija};` : "border-radius:0 14px 14px 0;";
  const srednje = `<td class="k-sredina" width="${sredina}%" valign="top" style="width:${sredina}%;padding:16px 14px;${desniRob}">`
    + `<p class="k-oznaka" style="margin:0;font-size:10px;line-height:1.3;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;color:${B.modra_temna}">${N(k.vrsta)}</p>`
    + `<p class="k-naslov" style="margin:4px 0 0;font-size:20px;line-height:1.15;font-weight:800;color:${B.karta_besedilo}">${N(k.naslov)}</p>`
    + vrstice + `</td>`;
  const desno = k.plakat
    ? `<td class="k-desno" width="24%" valign="middle" bgcolor="${B.plakat_ozadje}" style="width:24%;background:${B.plakat_ozadje};padding:0;border-radius:0 14px 14px 0">`
      + `<img src="cid:${CID_PLAKAT}" width="144" alt="" style="display:block;width:100%;height:auto;border:0;border-radius:0 14px 14px 0"></td>`
    : "";
  return `<table role="presentation" class="k-karta" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${B.karta}" style="width:100%;border-collapse:separate;border-spacing:0;background:${B.karta};border-radius:14px;font-family:${PISAVA};color:${B.karta_besedilo}"><tr>`
    + levo + srednje + desno + `</tr></table>`;
}

// --- ovoj celega maila ---
// Telefon (do 480 px): manjse pisave na karti, da so trije stolpci berljivi; odjemalec brez medijskih poizvedb pokaze iste stolpce z vecjo pisavo.
const SLOG = `body{margin:0;padding:0;background:${B.ozadje}}a{color:${B.besedilo}}`
  + `@media (max-width:480px){.k-levo{padding:12px 6px !important}.k-sredina{padding:12px 8px !important}.k-naslov{font-size:15px !important}`
  + `.k-vrednost{font-size:11px !important}.k-oznaka{font-size:9px !important}.k-mali{font-size:10px !important}.o-zunaj{padding:16px 8px !important}}`;
function ovoj(jez, vsebina) {
  return `<!doctype html><html lang="${jez}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark"><style>${SLOG}</style></head>`
    + `<body style="margin:0;padding:0;background:${B.ozadje}">`
    + `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${B.ozadje}" style="width:100%;background:${B.ozadje}"><tr>`
    + `<td class="o-zunaj" align="center" style="padding:24px 12px">`
    + `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px"><tr>`
    + `<td style="font-family:${PISAVA};font-size:15px;line-height:1.5;color:${B.besedilo};text-align:left;overflow-wrap:anywhere;word-break:break-word">`
    + vsebina + `<!--noga--></td></tr></table></td></tr></table></body></html>`;
}
const glava = (oznaka, naslov) => `<p style="margin:0 0 6px;font-size:13px;font-weight:600;letter-spacing:0.6px;text-transform:uppercase;color:${B.oznaka}">${ubezi(oznaka)}</p>`
  + `<h1 style="margin:0 0 18px;font-size:24px;line-height:1.2;font-weight:800;color:${B.besedilo}">${ubezi(naslov)}</h1>`;
const gumb = (href, besedilo) => `<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:20px 0 0"><tr>`
  + `<td align="center" bgcolor="${B.gumb}" style="background:${B.gumb};border-radius:14px"><a href="${ubezi(href)}" style="display:block;padding:15px 20px;font-family:${PISAVA};font-size:16px;font-weight:700;color:#FFFFFF;text-decoration:none">${ubezi(besedilo)}</a></td></tr></table>`;
const locilo = `<hr style="margin:32px 0 24px;border:0;border-top:1px solid ${B.crta}">`;
// Noga s firmo (nogaMaila v index.js) gre namesto oznake <!--noga--> v temnem slogu.
const nogaHtml = (n) => `<p style="margin:32px 0 0;font-family:${PISAVA};font-size:12px;line-height:1.5;color:${B.noga}">${n}</p>`;

module.exports = {
  ubezi, B, SLOG_DROBNO, karta, ovoj, glava, gumb, locilo, nogaHtml, datumKarta,
  prilogaLogo, prilogaPlakat, plakatZaMail, plakatUrlZaMail, CID_LOGO, CID_PLAKAT,
};
