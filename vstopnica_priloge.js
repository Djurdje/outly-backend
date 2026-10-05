"use strict";
/**
 * Priloge maila z vstopnico (prenos prijatelju brez racuna, migracija 034; potrdilo gostujocega nakupa, 033):
 *   - qrPng(koda)      kodo QR kot PNG (vgrajena slika v mailu, CID)
 *   - pdfVstopnice()   PDF s kodo QR in podatki dogodka (ena stran na vstopnico)
 *
 * Najmanjsa varna pot (Martin, 5. 10. 2026): ena majhna odvisnost brez lastnih odvisnosti (qrcode-generator, MIT) za matriko QR;
 * PNG zapisemo sami z vgrajenim `zlib`, PDF sestavimo rocno (osnovna pisava Helvetica, WinAnsi, brez vdelanih pisav). Brez pdfkit
 * (~10 odvisnosti) in brez knjiznic za slike. Znaki izven WinAnsi (c, c, d, ...) se v PDF poenostavijo (c -> c): PDF je pripomocek,
 * merodajna je koda QR; besedilo maila ima polne znake.
 */
const zlib = require("zlib");
const qrcode = require("qrcode-generator");

// --- QR matrika ---
// Raven M (15 % popravljanja): ~150-znakovna koda v2 (podpis Ed25519) da ~57 x 57 modulov. Se bere z zaslona in s papirja.
// Izracun matrike je najdrazji korak (~7 ms, blokira zanko dogodkov): PNG in PDF iste kode ga delita (majhen predpomnilnik zadnjih kod).
const matrikaPredpomnilnik = new Map();
function qrMatrika(koda) {
  const k = String(koda);
  let m = matrikaPredpomnilnik.get(k);
  if (m) return m;
  const qr = qrcode(0, "M");
  qr.addData(k, "Byte");
  qr.make();
  const n = qr.getModuleCount();
  m = { n, temen: (v, s) => qr.isDark(v, s) };
  if (matrikaPredpomnilnik.size >= 16) matrikaPredpomnilnik.delete(matrikaPredpomnilnik.keys().next().value);
  matrikaPredpomnilnik.set(k, m);
  return m;
}

// --- PNG ---
const CRC_TABELA = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[i] = c >>> 0; }
  return t;
})();
function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TABELA[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
function pngKos(tip, podatki) {
  const dolzina = Buffer.alloc(4); dolzina.writeUInt32BE(podatki.length);
  const jedro = Buffer.concat([Buffer.from(tip, "latin1"), podatki]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(jedro));
  return Buffer.concat([dolzina, jedro, crc]);
}
// Sivinska slika 8 bit (0 = crno, 255 = belo); `modul` pikslov na modul, `rob` modulov praznega roba (vsaj 4 po standardu).
function qrPng(koda, modul = 8, rob = 4) {
  const { n, temen } = qrMatrika(koda);
  const stran = (n + 2 * rob) * modul;
  const vrstica = 1 + stran;
  const surovo = Buffer.alloc(vrstica * stran, 0xFF);
  for (let y = 0; y < stran; y++) {
    surovo[y * vrstica] = 0;   // filter: brez
    const v = Math.floor(y / modul) - rob;
    if (v < 0 || v >= n) continue;
    for (let s = 0; s < n; s++) {
      if (!temen(v, s)) continue;
      const x0 = (s + rob) * modul;
      surovo.fill(0x00, y * vrstica + 1 + x0, y * vrstica + 1 + x0 + modul);
    }
  }
  const glava = Buffer.alloc(13);
  glava.writeUInt32BE(stran, 0); glava.writeUInt32BE(stran, 4); glava[8] = 8; glava[9] = 0; glava[10] = 0; glava[11] = 0; glava[12] = 0;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), pngKos("IHDR", glava),
    pngKos("IDAT", zlib.deflateSync(surovo, { level: 9 })), pngKos("IEND", Buffer.alloc(0))]);
}

// --- PDF ---
// Sirine znakov Helvetica (Adobe AFM) za ASCII 32..126, enota 1/1000 pisave; ostali znaki 556. Krepko: ~8 % sirse (previdno za lom vrstic).
const HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
  1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
  333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584];
const sirina = (s, velikost, krepko) => {
  let w = 0;
  for (const z of s) { const k = z.codePointAt(0); w += (k >= 32 && k <= 126 ? HELV[k - 32] : 556); }
  return (w / 1000) * velikost * (krepko ? 1.08 : 1);
};

// Besedilo -> niz znakov WinAnsi (cp1252), kot jih bere pisava Helvetica. c/c/d... poenostavimo, neznano -> '?'.
const CP1252 = { "€": 0x80, "…": 0x85, "‘": 0x91, "’": 0x92, "“": 0x93, "”": 0x94, "•": 0x95, "–": 0x96, "—": 0x97, "Š": 0x8A, "š": 0x9A, "Ž": 0x8E, "ž": 0x9E, "Œ": 0x8C, "œ": 0x9C };
const PRIPOMOCKI = { "č": "c", "Č": "C", "ć": "c", "Ć": "C", "đ": "d", "Đ": "D", "ł": "l", "Ł": "L", "ő": "o", "Ő": "O", "ű": "u", "Ű": "U", "ř": "r", "Ř": "R", "ě": "e", "Ě": "E", "ň": "n", "Ň": "N" };
function winAnsi(s) {
  let r = "";
  for (const z of String(s).normalize("NFC")) {
    const k = z.codePointAt(0);
    if (k >= 32 && k <= 126) r += z;
    else if (k >= 0x80 && k <= 0xFF) r += String.fromCharCode(k);   // 0x80-0x9F: ze pretvorjeno (idempotentno), 0xA0-0xFF: enako v latin1 in cp1252
    else if (CP1252[z] !== undefined) r += String.fromCharCode(CP1252[z]);
    else if (PRIPOMOCKI[z]) r += PRIPOMOCKI[z];
    else {
      const osnova = z.normalize("NFD").replace(/[̀-ͯ]/g, "");
      r += osnova.length === 1 && osnova.charCodeAt(0) >= 32 && osnova.charCodeAt(0) <= 126 ? osnova : "?";
    }
  }
  return r;
}
// Za izris in merjenje je dovolj poenostavljena oblika (po poenostavitvi je sirina znana).
const pdfNiz = (s) => "(" + winAnsi(s).replace(/[\\()]/g, (c) => "\\" + c) + ")";
const poenostavi = (s) => winAnsi(s);

function prelomi(besedilo, velikost, krepko, najvecSirina) {
  const vrstice = [];
  for (const odstavek of String(besedilo).split("\n")) {
    let tren = "";
    for (const beseda of poenostavi(odstavek).split(/\s+/).filter(Boolean)) {
      // predolga beseda (npr. povezava): razreze po znakih
      let b = beseda;
      while (sirina(b, velikost, krepko) > najvecSirina) {
        let i = b.length; while (i > 1 && sirina(b.slice(0, i), velikost, krepko) > najvecSirina) i--;
        if (tren) { vrstice.push(tren); tren = ""; }
        vrstice.push(b.slice(0, i)); b = b.slice(i);
      }
      const poskus = tren ? tren + " " + b : b;
      if (sirina(poskus, velikost, krepko) <= najvecSirina) tren = poskus;
      else { vrstice.push(tren); tren = b; }
    }
    vrstice.push(tren);
  }
  return vrstice;
}

const A4 = [595.28, 841.89];
const f2 = (x) => (Math.round(x * 100) / 100).toString();

/**
 * Ena stran na vstopnico. `dogodek`: { naslov, zacetek (niz, ze oblikovan), prizoriscePodatki (niz), starost (niz ali ""), organizator (niz ali "") };
 * `vstopnice`: [{ koda (vsebina QR), vrsta (niz, npr. "Standard ticket"), oznaka (npr. "Ticket 1 of 2") }]; `varnost`: besedilo pod kodo.
 * PDF nima e-naslova prejemnika in nobene povezave z zetonom (lahko ga kdo posreduje; vstopnica je tako ali tako koda QR).
 */
function pdfVstopnice({ dogodek, vstopnice, varnost, naslovDokumenta = "Outly ticket" }) {
  const strani = [];
  for (const v of vstopnice) {
    const op = [];
    const bes = (x, y, velikost, krepko, besedilo, siva = 0) => op.push(`BT /${krepko ? "F2" : "F1"} ${velikost} Tf ${siva} g ${f2(x)} ${f2(y)} Td ${pdfNiz(besedilo)} Tj ET`);
    const levo = 56, desno = A4[0] - 56, sir = desno - levo;
    let y = A4[1] - 72;
    bes(levo, y, 11, true, "OUTLY TICKET", 0.35); y -= 30;
    for (const vr of prelomi(dogodek.naslov, 22, true, sir)) { bes(levo, y, 22, true, vr); y -= 27; }
    y -= 4;
    for (const [vel, krepko, besedilo, siva] of [[13, false, dogodek.zacetek, 0], [12, false, dogodek.prizoriscePodatki, 0.2], [12, true, dogodek.starost, 0], [12, false, v.vrsta, 0.2], [10, false, dogodek.organizator, 0.35]]) {
      if (!besedilo) continue;
      for (const vr of prelomi(besedilo, vel, krepko, sir)) { bes(levo, y, vel, krepko, vr, siva); y -= vel * 1.45; }
      y -= 4;
    }
    if (v.oznaka) { bes(levo, y, 11, false, v.oznaka, 0.35); y -= 18; }
    // koda QR (vektorsko, 250 x 250 pt, rob 4 moduli)
    const { n, temen } = qrMatrika(v.koda);
    const rob = 4, velikost = 250, modul = velikost / (n + 2 * rob);
    const x0 = (A4[0] - velikost) / 2, y0 = y - 12 - velikost;
    op.push("q 0 g");
    for (let r = 0; r < n; r++) {
      let s = 0;
      while (s < n) {
        if (!temen(r, s)) { s++; continue; }
        let e = s; while (e < n && temen(r, e)) e++;
        op.push(`${f2(x0 + (s + rob) * modul)} ${f2(y0 + velikost - (r + rob + 1) * modul)} ${f2((e - s) * modul + 0.02)} ${f2(modul + 0.02)} re f`);
        s = e;
      }
    }
    op.push("Q");
    y = y0 - 28;
    for (const vr of prelomi(varnost, 10.5, false, sir)) { bes(levo, y, 10.5, false, vr, 0.15); y -= 15; }
    bes(levo, 48, 9, false, "outly.si", 0.45);
    strani.push(op.join("\n"));
  }

  // Sestava datoteke: 1 Catalog, 2 Pages, 3 F1, 4 F2, 5 Info, nato za vsako stran (Page, Contents).
  const objekti = [];
  const kidsId = strani.map((_, i) => 6 + i * 2);
  objekti[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objekti[2] = `<< /Type /Pages /Kids [${kidsId.map((i) => `${i} 0 R`).join(" ")}] /Count ${strani.length} >>`;
  objekti[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
  objekti[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>";
  objekti[5] = `<< /Title ${pdfNiz(naslovDokumenta)} /Producer (Outly) >>`;
  strani.forEach((vsebina, i) => {
    const id = 6 + i * 2;
    objekti[id] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${f2(A4[0])} ${f2(A4[1])}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${id + 1} 0 R >>`;
    objekti[id + 1] = { tok: vsebina };
  });
  const deli = [Buffer.from("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n", "latin1")];
  const odmiki = [];
  let pozicija = deli[0].length;
  for (let i = 1; i < objekti.length; i++) {
    const o = objekti[i];
    const telo = typeof o === "string" ? o : `<< /Length ${Buffer.byteLength(o.tok, "latin1")} >>\nstream\n${o.tok}\nendstream`;
    const b = Buffer.from(`${i} 0 obj\n${telo}\nendobj\n`, "latin1");
    odmiki[i] = pozicija; pozicija += b.length; deli.push(b);
  }
  let xref = `xref\n0 ${objekti.length}\n0000000000 65535 f \n`;
  for (let i = 1; i < objekti.length; i++) xref += String(odmiki[i]).padStart(10, "0") + " 00000 n \n";
  xref += `trailer\n<< /Size ${objekti.length} /Root 1 0 R /Info 5 0 R >>\nstartxref\n${pozicija}\n%%EOF\n`;
  deli.push(Buffer.from(xref, "latin1"));
  return Buffer.concat(deli);
}

module.exports = { qrMatrika, qrPng, pdfVstopnice, winAnsi, crc32 };
