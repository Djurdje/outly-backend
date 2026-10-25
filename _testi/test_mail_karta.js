#!/usr/bin/env node
/**
 * Mail z vstopnico v obliki karte (mail_karta.js, Martin 24. 10. 2026). Brez baze in streznika:
 *   node _testi/test_mail_karta.js
 *   1  plakat: samo z NASEGA Cloudinaryja (SSRF), izrez za mail, rok, velikost, tip, predpomnilnik (tudi neuspeha)
 *   2  karta: tri stolpci (levo logotip + QR, sredina podatki, desno plakat), brez plakata dva, brez kode QR besedilo, ubezanje podatkov
 *   3  ovoj: temno ozadje, oznaka za nogo, brez zunanjih virov in skritega besedila
 * Integracija (pravi maili, plakat v potrdilu kupcu in mailu gostu, noga): test_potrdilo_kupcu.js sklop 10; karta brez plakata: test_gost.js, test_prenos_gost.js.
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
      [P + "../../tujoblak/image/upload/a.jpg", "pot z .."], [P + "v1/a.jpg?x=1", "poizvedba"],
      [P + "v1/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/tujoblak/image/fetch/x.jpg", "pot z %2e%2e (fetch jo normalizira v ..)"], [P + "v1/.%2e/a.jpg", "pot z .%2e"],
      [P + "v1/%2E%2E/a.jpg", "pot z %2E%2E"], [P + "v1\\..\\a.jpg", "povratna posevnica"], [P + "v1/./a.jpg", "pot z /./"], [P + "v1//a.jpg", "dvojna posevnica"],
      [P + "v1/a.jpg#x", "fragment"], [P + "v1/a b.jpg", "presledek"], [P + "v1/a@b.jpg", "@"], [P + "v1/.", "segment . na koncu (fetch ga odstrani)"], [P, "prazna pot"], [P + "a".repeat(500), "predolg URL"], ["", "prazno"], [null, "null"]]) {
      assert(K.plakatUrlZaMail(u) === null, `zavrnjen: ${opis}`);
    }
    assert(K.plakatUrlZaMail(P + "v1/a.jpg", "") === null, "brez CLOUDINARY_CLOUD_NAME: brez plakata");
    assert(K.plakatUrlZaMail(P + "c_fill,w_500/v17/klub_1/plakat-2.jpg") === P + "c_fill,g_auto,w_300,h_600,f_jpg,q_70/c_fill,w_500/v17/klub_1/plakat-2.jpg", "obstojec izrez v URL-ju (vejica) je dovoljen");

    let b = await K.plakatZaMail(P + "v1/ok.jpg");
    assert(b && b.equals(JPEG) && klici.length === 1 && klici[0].opt.redirect === "error" && klici[0].opt.signal, "prenos: JPEG, brez preusmeritev, z rokom (signal)", klici.map(k => k.url));
    b = await K.plakatZaMail(P + "v1/ok.jpg");
    assert(b && klici.length === 1, "drugi klic iz predpomnilnika (en prenos na dogodek ob navali nakupov)", klici.length);
    assert(await K.plakatZaMail("https://example.com/a.jpg") === null && klici.length === 1, "tuj URL: brez omreznega klica");
    let spusti; const zadrzan = new Promise((r) => { spusti = r; });
    odziv = async () => { await zadrzan; return new Response(JPEG, { status: 200, headers: { "content-type": "image/jpeg" } }); };
    const hkratni = [1, 2, 3, 4, 5].map(() => K.plakatZaMail(P + "v1/naval.jpg"));
    await new Promise((r) => setImmediate(r));
    spusti();
    const rez = await Promise.all(hkratni);
    assert(rez.every((x) => x && x.equals(JPEG)) && klici.length === 2, "5 hkratnih klicev za isti plakat (naval nakupov): en prenos", klici.length);

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
    // Martinov posnetek 25. 10. 2026: v temnem nacinu odjemalca je bil srednji stolpec crn (celica brez lastne barve). Vsaka celica karte ima bgcolor IN background.
    const celice = h3.match(/<td\b[^>]*>/g) || [];
    assert(celice.length >= 10 && celice.every((t) => /bgcolor="#[0-9A-F]{6}"/i.test(t) && /style="background:#[0-9A-F]{6};/i.test(t)), "vsaka celica karte ima svojo barvo (bgcolor + background): temni nacin je ne pobarva",
      celice.filter((t) => !/bgcolor=/.test(t)).slice(0, 2));
    assert(/class="k-sredina"[^>]*bgcolor="#FFFFFF"|bgcolor="#FFFFFF"[^>]*class="k-sredina"/.test(h3), "srednji stolpec je bel (#FFFFFF)");
    const izrezi = h3.match(/<div style="width:20px;height:10px;margin:0 auto;background:#000000;border-radius:[^"]+">/g) || [];
    assert(izrezi.length === 4 && (h3.match(/border-right:2px dashed #D0D0D6/g) || []).length === 2, "plakat: dve perforaciji, vsaka z izrezom zgoraj in spodaj (20 px, barva ozadja maila)", izrezi.length);
    const h2 = K.karta({ ...osnova, plakat: false });
    assert((h2.match(/<div style="width:20px;height:10px;margin:0 auto;background:#000000;/g) || []).length === 2, "brez plakata: ena perforacija z dvema izrezoma");
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
    assert(K.nogaHtml("X").includes("color:#A1A1A6") && K.SLOG_DROBNO.includes("font-size:13px") && K.SLOG_DROBNO.includes("color:#A1A1A6"), "noga in drobni tisk: berljiva siva na crni (13 px)");
    const lg = K.prilogaLogo();
    const lgB = Buffer.from(lg.content, "base64");
    assert(lgB.readUInt32BE(16) === 192 && lgB.readUInt32BE(20) === 74 && /src="cid:outly-logo" width="96" alt="Outly"/.test(h3) && !/>Outly<\/td>/.test(h3),
      "logotip je napis Outly (192 x 74, prikaz 96 px), ne ikona z besedilom (Martin 25. 10.)", [lgB.readUInt32BE(16), lgB.readUInt32BE(20)]);
    assert(lg.content_id === "outly-logo" && lg.content_type === "image/png" && Buffer.from(lg.content, "base64").subarray(1, 4).toString() === "PNG", "logotip: PNG priloga (CID)");
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA v testu:", e && e.stack || e);
  }
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
