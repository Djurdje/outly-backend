#!/usr/bin/env node
/**
 * Mail z vstopnico v obliki karte (mail_karta.js, Martin 24. 10. 2026). Brez baze in streznika:
 *   node _testi/test_mail_karta.js
 *   1  plakat: samo z NASEGA Cloudinaryja (SSRF), izrez za mail, rok, velikost, tip, predpomnilnik (tudi neuspeha)
 *   2  karta: tri stolpci (levo logotip + QR, sredina podatki, desno plakat), brez plakata dva, brez kode QR besedilo, ubezanje podatkov
 *   3  ovoj: temno ozadje, oznaka za nogo, brez zunanjih virov in skritega besedila
 * Integracija (pravi maili, plakat v potrdilu kupcu, noga): test_potrdilo_kupcu.js sklop 10, test_gost.js, test_prenos_gost.js.
 */
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

process.env.CLOUDINARY_CLOUD_NAME = "nasoblak";
const K = require("../mail_karta");
const JPEG = Buffer.from("ffd8ffe000104a46494600010100000100010000ffd9", "hex");
const klici = [];
let odziv = () => new Response(JPEG, { status: 200, headers: { "content-type": "image/jpeg", "content-length": String(JPEG.length) } });
global.fetch = async (url, opt) => { klici.push({ url: String(url), opt }); return odziv(url, opt); };

(async () => {
  try {
    console.log("\n# 1. Plakat");
    const P = "https://res.cloudinary.com/nasoblak/image/upload/";
    assert(K.plakatUrlZaMail(P + "v17/klub/plakat.jpg") === P + "c_fill,g_auto,w_300,h_600,f_jpg,q_70/v17/klub/plakat.jpg", "nas Cloudinary: ozek pokoncni izrez (1 : 2, JPEG)");
    for (const [u, opis] of [["https://res.cloudinary.com/tujoblak/image/upload/v1/a.jpg", "tuj Cloudinary racun"], ["http://res.cloudinary.com/nasoblak/image/upload/v1/a.jpg", "http"],
      ["https://example.com/image/upload/v1/a.jpg", "tuj streznik"], ["https://res.cloudinary.com.evil.test/nasoblak/image/upload/a.jpg", "podobna domena"],
      [P + "../../tujoblak/image/upload/a.jpg", "pot z .."], [P + "v1/a.jpg?x=1", "poizvedba"], [P, "prazna pot"], [P + "a".repeat(500), "predolg URL"], ["", "prazno"], [null, "null"]]) {
      assert(K.plakatUrlZaMail(u) === null, `zavrnjen: ${opis}`);
    }
    assert(K.plakatUrlZaMail(P + "v1/a.jpg", "") === null, "brez CLOUDINARY_CLOUD_NAME: brez plakata");

    let b = await K.plakatZaMail(P + "v1/ok.jpg");
    assert(b && b.equals(JPEG) && klici.length === 1 && klici[0].opt.redirect === "error" && klici[0].opt.signal, "prenos: JPEG, brez preusmeritev, z rokom (signal)", klici.map(k => k.url));
    b = await K.plakatZaMail(P + "v1/ok.jpg");
    assert(b && klici.length === 1, "drugi klic iz predpomnilnika (en prenos na dogodek ob navali nakupov)", klici.length);
    assert(await K.plakatZaMail("https://example.com/a.jpg") === null && klici.length === 1, "tuj URL: brez omreznega klica");

    odziv = () => new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } });
    assert(await K.plakatZaMail(P + "v1/html.jpg") === null, "odgovor ni JPEG: brez plakata");
    const n = klici.length;
    assert(await K.plakatZaMail(P + "v1/html.jpg") === null && klici.length === n, "neuspeh je v predpomnilniku (ne ponavlja ob vsakem mailu)");
    odziv = () => new Response(Buffer.alloc(500 * 1024, 0xFF), { status: 200, headers: { "content-type": "image/jpeg", "content-length": String(500 * 1024) } });
    assert(await K.plakatZaMail(P + "v1/velik.jpg") === null, "prevelik (glava content-length): brez plakata");
    odziv = () => new Response(Buffer.concat([JPEG, Buffer.alloc(500 * 1024)]), { status: 200, headers: { "content-type": "image/jpeg" } });
    assert(await K.plakatZaMail(P + "v1/velik2.jpg") === null, "prevelik (brez glave): brez plakata");
    odziv = () => new Response("napaka", { status: 404, headers: { "content-type": "image/jpeg" } });
    assert(await K.plakatZaMail(P + "v1/404.jpg") === null, "404: brez plakata");
    odziv = () => { throw new TypeError("fetch failed"); };
    assert(await K.plakatZaMail(P + "v1/omrezje.jpg") === null, "napaka omrezja: brez plakata (ne vrze)");
    odziv = (u, opt) => new Promise((_, rej) => opt.signal.addEventListener("abort", () => rej(new Error("aborted"))));
    const t0 = Date.now();
    assert(await K.plakatZaMail(P + "v1/visi.jpg") === null && Date.now() - t0 < 4500, "Cloudinary visi: po roku (3 s) brez plakata", Date.now() - t0);

    console.log("\n# 2. Karta");
    const osnova = { jez: "sl", vrsta: "Vstopnica", naslov: "Noc & <b>x</b>", vrstice: [["Datum", "ned, 1. 11. 2026 · 23:00"], ["Prizorišče", "Klub <i>", true], null, ["Prazno", ""]],
      qr: { cid: "ticket-qr-1", alt: "Koda QR vstopnice", oznaka: "Vstopnica 1 od 2" }, brezQr: "Kode QR so v aplikaciji Outly", pod: ["OUT-ABC", "Pokažite pri vhodu"] };
    const h3 = K.karta({ ...osnova, plakat: true });
    const i = (s) => h3.indexOf(s);
    assert(i('class="k-levo" width="34%"') > 0 && i('class="k-sredina" width="42%"') > i('class="k-levo"') && i('class="k-desno" width="24%"') > i('class="k-sredina"'), "plakat: trije stolpci 34 / 42 / 24 %");
    assert(i('src="cid:outly-logo"') < i('src="cid:ticket-qr-1"') && i('src="cid:ticket-qr-1"') < i('class="k-sredina"') && i(">Vstopnica 1 od 2<") < i('class="k-sredina"') && i("OUT-ABC") < i('class="k-sredina"'),
      "levo: logotip, koda QR, oznaka in podatki pod kodo");
    assert(i('src="cid:event-poster"') > i('class="k-desno"') && /max-width:150px/.test(h3), "desno plakat; koda QR do 150 px (na telefonu stolpec 34 %)");
    assert(h3.includes("Noc &amp; &lt;b&gt;x&lt;/b&gt;") && h3.includes("Klub &lt;i&gt;") && !h3.includes("<b>x") && !h3.includes(">Prazno<"), "podatki ubezeni; prazne vrstice izpuscene");
    const h2 = K.karta({ ...osnova, plakat: false });
    assert(h2.includes('class="k-sredina" width="66%"') && !h2.includes("k-desno") && !h2.includes("event-poster"), "brez plakata: dva stolpca, sredina 66 %");
    const h0 = K.karta({ ...osnova, qr: null, plakat: false });
    assert(!h0.includes("ticket-qr") && h0.includes("Kode QR so v aplikaciji Outly"), "brez kode QR: besedilo namesto kode");
    assert(!/display:\s*flex|display:\s*grid|position:\s*absolute/i.test(h3 + h2), "postavitev s tabelami (Outlook/Gmail), brez flex/grid/absolute");
    assert(K.datumKarta("2026-11-01T22:00:00Z", "sl") === "ned, 1. 11. 2026 · 23:00" && K.datumKarta("2026-11-01T22:00:00Z", "en") === "Sun, 1 Nov 2026 · 23:00", "datum na karti po ljubljanskem casu (sl, en)",
      [K.datumKarta("2026-11-01T22:00:00Z", "sl"), K.datumKarta("2026-11-01T22:00:00Z", "en")]);

    console.log("\n# 3. Ovoj");
    const ov = K.ovoj("sl", "<p>vsebina</p>");
    assert(ov.startsWith("<!doctype html>") && /bgcolor="#000000"/.test(ov) && ov.includes("max-width:600px") && ov.includes("<!--noga-->") && ov.indexOf("<!--noga-->") < ov.indexOf("</body>"), "temen ovoj (600 px), oznaka za nogo znotraj");
    assert(!/<link|@import|https?:\/\/|<script|display:\s*none/i.test(ov + h3), "brez zunanjih virov, skriptov in skritega besedila");
    assert(/@media \(max-width:480px\)/.test(ov) && /\.k-vrednost\{font-size:11px/.test(ov), "telefon: manjse pisave na karti (stolpci ostanejo vodoravni)");
    assert(K.nogaHtml("X").includes("color:#8E8E93") && K.SLOG_DROBNO.includes("font-size:13px") && K.SLOG_DROBNO.includes("color:#A1A1A6"), "noga in drobni tisk: berljiva siva na crni (13 px)");
    const lg = K.prilogaLogo();
    assert(lg.content_id === "outly-logo" && lg.content_type === "image/png" && Buffer.from(lg.content, "base64").subarray(1, 4).toString() === "PNG", "logotip: PNG priloga (CID)");
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA v testu:", e && e.stack || e);
  }
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
