#!/usr/bin/env node
/**
 * Mail Martinu ob opozorilu `sken_ni_pripravljen` (#406, migracija 076, I71; sken_opozorilo.js). Zagon (PG16, prazna baza z migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_sken_opozorilo_mail.js
 * Lokalni JWKS 6930, lazni Resend 6931; strezniki A 6932 + B 6933 (dva procesa na isti bazi), C 6934 (brez prejemnika), D 6935 (samo AGENT_NUJNO_MAIL).
 *
 *  M1  dogodek v oknu z veljavno vstopnico brez prenosa -> natanko 1 mail, komu: OPOZORILA_MAIL (ne AGENT_NUJNO_MAIL); SL + EN, naslov, klub, cas
 *  M2  dva procesa na isti bazi, vec krogov -> se vedno 1 mail na dogodek; po restartu procesa tudi
 *  M3  brez maila: prenos obstaja, dogodek izven okna, brez vstopnic, osnutek, odpovedan, skrit klub; isti nabor kot opozorilo v panelu (ena resnica)
 *  M4  vsebina: brez e-naslovov kupcev, HTML naslova in kluba ubezan, glava zadeve brez prelomov vrstic
 *  M5  nov dogodek pozneje -> mail ob naslednjem krogu; evidenca sken_opozorila_poslana
 *  M6  Resend { error } (422) -> ponovitev po premoru, na koncu 1 sprejet mail; trajna napaka -> najvec 5 poskusov, POZOR, nic ne pade
 *  M8  velika prestavitev (>= 1 h, > 1 h po mailu) -> nov mail; seznam prenesen med pošiljanjem -> ne pošlje, poskus se ne šteje
 *  M9  počasen Resend (odgovor po 1 s, premor 300 ms) in dva procesa -> natanko 1 mail (premor prevzema je vedno > rok Resenda)
 *  M10 Resend 429, 5xx in molk (iztek roka) -> ponovitev, na koncu natanko 1 sprejet mail; po 5 neuspehih mail ni izgubljen (redka ponovitev)
 *  M11 lastnik premika dogodek vsako minuto za 1 min (10 krogov) -> 1 mail; M12 premik >= 1 h po > 1 h -> 2. mail, takoj nato spet -> ne
 *  M13 5 velikih premikov -> TRDA MEJA 3 maili; M14 pocasen Resend, ki sprejme po roku, vedno -> najvec 10 zahtevkov (trda meja), POZOR
 *  M15 prestavitev med pocasnim posiljanjem: stari mail ne oznaci novega termina kot poslanega
 *  M7  brez prejemnika / brez Resenda: 0 mailov, `[sken-opozorilo] POZOR`, proces zivi; samo AGENT_NUJNO_MAIL -> mail gre tja
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 6930, RESEND_PORT = 6931, PA = 6932, PB = 6933, PC = 6934, PD = 6935, PE = 6936, PF = 6937, PH = 6938;
const KID = "test-kid-sken-mail";
const MAIL_OPOZ = "opozorila-martin@outly.test", MAIL_NUJNO = "nujno-martin@outly.test";
const KUPEC = "kupec-skenmail@primer.si";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});
const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
function jwt(email, sub) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${JWKS_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now, user_metadata: { email_verified: true, username: email.split("@")[0].replace(/[^a-z0-9_]/gi, "") } });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

// Lazni Resend: R.vsi = vsi zahtevki, R.poslano = sprejeti; R.zavrni(m) -> true = 422 (dokazana zavrnitev PRED obdelavo); R.nacin(m) -> "429" | "500" | "molk" (ne odgovori);
// R.zakasnitev(m) = ms do odgovora; R.naPrejem(m) = kavelj ob prejemu zahtevka
const R = { vsi: [], poslano: [], zavrni: () => false, nacin: () => null, zakasnitev: () => 0, naPrejem: () => {} };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", (x) => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      const m = JSON.parse(d); R.vsi.push(m); R.naPrejem(m);
      const odgovori = () => {
        const nacin = R.nacin(m);
        if (nacin === "molk") return setTimeout(() => req.socket.destroy(), 4000);   // odjemalec odneha ob izteku roka
        if (nacin === "429") { res.writeHead(429, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "rate_limit_exceeded", message: "stub: 429", statusCode: 429 })); }
        if (nacin === "500") { res.writeHead(500, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "internal_server_error", message: "stub: 500", statusCode: 500 })); }
        if (R.zavrni(m)) { res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub: zavrnjeno", statusCode: 422 })); }
        R.poslano.push(m); res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + R.poslano.length }));
      };
      const z = R.zakasnitev(m);
      return z > 0 ? setTimeout(odgovori, z) : odgovori();
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const zaDogodek = (arr, naslov) => arr.filter((m) => String(m.subject || "").includes(naslov));
const prejemniki = (m) => (Array.isArray(m.to) ? m.to : [m.to]);

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 600) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));
async function cakaj(pogoj, ms = 8000) { const t = Date.now() + ms; while (Date.now() < t) { if (await pogoj()) return true; await spi(80); } return false; }
function zazeni(port, okolje) {
  const proc = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "",
    RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", GOST_POSTA_TIMEOUT_MS: "600",
    ADMIN_NADZOR_PREDPOMNILNIK_MS: "0", REZERVACIJE_CISCENJE_MS: "0", OPOZORILA_MAIL: "", AGENT_NUJNO_MAIL: "", SKEN_OPOZORILO_MS: "300", SKEN_OPOZORILO_PREMOR_MS: "500", SKEN_OPOZORILO_DOLGI_PREMOR_MS: "6000", ...okolje },
    stdio: ["ignore", "pipe", "pipe"], cwd: require("path").join(__dirname, "..") });
  const o = { proc, log: "", port, ustavi: () => new Promise((r) => { if (proc.exitCode !== null || proc.signalCode !== null) return r(); proc.once("exit", r); proc.kill(); }) };
  proc.stdout.on("data", (d) => o.log += d); proc.stderr.on("data", (d) => o.log += d);
  return o;
}
async function cakajStreznik(port) { for (let i = 0; i < 150; i++) { try { await fetch(`http://127.0.0.1:${port}/`); return true; } catch { await spi(100); } } return false; }
async function api(port, pot, token) {
  const r = await fetch(`http://127.0.0.1:${port}${pot}`, { headers: { authorization: "Bearer " + token }, signal: AbortSignal.timeout(15000) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE sken_opozorila_poslana, sken_prenosi, admin_dejanja, agent_zetoni, omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  await new Promise((r) => resendServer.listen(RESEND_PORT, r));
  const procesi = [];
  const zaZagon = (port, okolje) => { const p = zazeni(port, okolje); procesi.push(p); return p; };
  try {
    // --- podatki: neposredno v bazo (kupec in admin nastaneta ob prvem /me) ---
    const A0 = zaZagon(PA, { OPOZORILA_MAIL: MAIL_OPOZ, AGENT_NUJNO_MAIL: MAIL_NUJNO, SKEN_OPOZORILO_MS: "0" });   // 0 = delavec izklopljen; samo za ustvarjanje uporabnikov
    assert(await cakajStreznik(PA), "streznik tece");
    const T = { admin: jwt("admin-skenmail@outly.si", uuid(1)), kupec: jwt(KUPEC, uuid(2)), lastnik: jwt("lastnik-skenmail@outly.si", uuid(3)) };
    for (const k of Object.keys(T)) { const r = await api(PA, "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin-skenmail@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik-skenmail@outly.si'");
    const uid = async (e) => (await pool.query("SELECT id FROM users WHERE email=$1", [e])).rows[0].id;
    const lastnik = await uid("lastnik-skenmail@outly.si"), kupec = await uid(KUPEC);
    const klub = (await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Klub Skenmail', 'Ljubljana') RETURNING id", [lastnik])).rows[0].id;
    const klubHtml = (await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Klub <b>&\"Html\"</b>', 'Ljubljana') RETURNING id", [lastnik])).rows[0].id;
    const klubSkrit = (await pool.query("INSERT INTO clubs (owner_user_id, name, city, hidden) VALUES ($1, 'Skrit Skenmail', 'Celje', true) RETURNING id", [lastnik])).rows[0].id;
    let stRef = 0;
    const dogodek = async ({ naslov, klubId = klub, start = "NOW() + INTERVAL '1 hour'", end = "NOW() + INTERVAL '7 hours'", status = "published", vstopnic = 1 }) => {
      const e = (await pool.query(
        `INSERT INTO events (club_id, title, status, start_at, end_at, ticket_price_cents, capacity, poster_url, description, genres)
         VALUES ($1, $2, $3, ${start}, ${end}, 1500, 100, 'https://x.test/p.jpg', 'opis', ARRAY['techno']) RETURNING id`, [klubId, naslov, status])).rows[0].id;
      if (vstopnic > 0) {
        const o = (await pool.query(
          `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, buyer_email, paid_at)
           VALUES ($1, $2, $3, $4, $5, 1500, $6, 'eur', 0, 'paid', $7, NOW()) RETURNING id`, ["SM" + (++stRef) + "X" + Date.now(), kupec, e, klubId, vstopnic, 1500 * vstopnic, KUPEC])).rows[0].id;
        for (let i = 0; i < vstopnic; i++) await pool.query("INSERT INTO tickets (order_id, event_id, holder_user_id) VALUES ($1, $2, $3)", [o, e, kupec]);
      }
      return e;
    };
    const N = { kmalu: "Kmalu Skenmail", html: "Html <script>alert(1)</script> & \"q\"", prenos: "Prenos Skenmail", daleko: "Daleko Skenmail", brez: "Brez vstopnic Skenmail",
      osnutek: "Osnutek Skenmail", odpovedan: "Odpovedan Skenmail", koncan: "Koncan Skenmail", skrit: "Skrit dogodek Skenmail" };
    const E = {};
    E.kmalu = await dogodek({ naslov: N.kmalu });
    E.html = await dogodek({ naslov: N.html, klubId: klubHtml, start: "NOW() + INTERVAL '30 minutes'", vstopnic: 2 });
    E.prenos = await dogodek({ naslov: N.prenos });
    await pool.query("INSERT INTO sken_prenosi (event_id, club_id, zadnji_prenos) VALUES ($1, $2, NOW() - INTERVAL '1 hour')", [E.prenos, klub]);
    E.daleko = await dogodek({ naslov: N.daleko, start: "NOW() + INTERVAL '5 hours'", end: "NOW() + INTERVAL '11 hours'" });
    E.brez = await dogodek({ naslov: N.brez, vstopnic: 0 });
    E.osnutek = await dogodek({ naslov: N.osnutek, status: "draft" });
    E.odpovedan = await dogodek({ naslov: N.odpovedan, status: "cancelled" });
    E.koncan = await dogodek({ naslov: N.koncan, start: "NOW() - INTERVAL '8 hours'", end: "NOW() - INTERVAL '2 hours'" });
    E.skrit = await dogodek({ naslov: N.skrit, klubId: klubSkrit });
    await A0.ustavi();

    // --- M1/M2: dva procesa na isti bazi ---
    console.log("\n# M1/M2: dva procesa (A, B), vec krogov");
    const A = zaZagon(PA, { OPOZORILA_MAIL: MAIL_OPOZ, AGENT_NUJNO_MAIL: MAIL_NUJNO });
    const B = zaZagon(PB, { OPOZORILA_MAIL: MAIL_OPOZ, AGENT_NUJNO_MAIL: MAIL_NUJNO });
    assert(await cakajStreznik(PA) && await cakajStreznik(PB), "procesa A in B tecta");
    assert(await cakaj(() => R.poslano.length >= 2), "mail za oba dogodka v oknu je prisel", R.poslano.map((m) => m.subject));
    await spi(2500);   // ~8 krogov vsakega procesa
    assert(zaDogodek(R.poslano, N.kmalu).length === 1, "dogodek v oknu brez prenosa: natanko 1 mail (dva procesa, vec krogov)", zaDogodek(R.poslano, N.kmalu).length);
    assert(zaDogodek(R.poslano, "Html").length === 1, "drugi dogodek v oknu: natanko 1 mail", zaDogodek(R.poslano, "Html").length);
    assert(R.poslano.length === 2, "skupaj 2 maila (ostali dogodki ne sprozijo)", R.poslano.map((m) => m.subject));
    assert(R.vsi.length === 2, "tudi poskusov posiljanja je natanko 2", R.vsi.length);
    const m1 = zaDogodek(R.poslano, N.kmalu)[0];
    assert(prejemniki(m1).length === 1 && prejemniki(m1)[0] === MAIL_OPOZ, "prejemnik je OPOZORILA_MAIL (ne AGENT_NUJNO_MAIL)", m1 && m1.to);
    assert(/Sken na vratih ni pripravljen/.test(m1.subject) && /Door scan not ready/.test(m1.subject), "zadeva SL + EN", m1.subject);
    assert(m1.text.includes(N.kmalu) && m1.text.includes("Klub Skenmail"), "besedilo vsebuje naslov dogodka in ime kluba");
    assert(/Začetek: .*\d{1,2}[.:]\d{2}/.test(m1.text) && /Starts: .*\d{1,2}:\d{2}/.test(m1.text), "cas zacetka v SL in EN", m1.text.split("\n").filter((l) => /Začetek|Starts/.test(l)));
    assert(m1.text.includes("sken ne bo deloval") && m1.text.includes("will not work") && m1.text.includes("odpre skener") && m1.text.includes("open the scanner"), "pomen in navodilo za Martina v SL in EN");
    assert(m1.text.includes("/admin/") && m1.html.includes("/admin/"), "povezava na panel");
    assert(m1.text.includes("NEXT DIMENSIONS") && m1.html.includes("NEXT DIMENSIONS"), "noga s firmo (kot vsak mail)");
    const ev = (await pool.query("SELECT event_id, poskusi, poslano_at FROM sken_opozorila_poslana ORDER BY event_id")).rows;
    assert(ev.length === 2 && ev.every((x) => x.poslano_at && x.poskusi === 1) && ev.map((x) => x.event_id).sort().join() === [E.kmalu, E.html].sort().join(), "evidenca: 2 vrstici, poslano_at, poskusi 1", ev);

    // --- M3: ena resnica s panelom ---
    console.log("\n# M3: isti nabor kot opozorilo v panelu");
    const op = await api(PA, "/admin/api/opozorila", T.admin);
    const panel = (op.body.items || []).filter((x) => x.vrsta === "sken_ni_pripravljen").map((x) => x.cilj_id).sort();
    assert(op.status === 200 && panel.join() === [E.kmalu, E.html].sort().join(), "panel opozarja na iste dogodke kot mail", { panel, status: op.status });
    for (const k of ["prenos", "daleko", "brez", "osnutek", "odpovedan", "koncan", "skrit"]) assert(zaDogodek(R.vsi, N[k]).length === 0, `${k}: brez maila`);

    // --- M4: vsebina ---
    console.log("\n# M4: vsebina");
    const m2 = zaDogodek(R.poslano, "Html")[0];
    const vse = JSON.stringify(R.poslano);
    assert(!vse.includes("kupec-skenmail") && !vse.includes("primer.si"), "brez e-naslova kupca");
    assert(!/[\w.+-]+@(?!outly)[\w-]+\.[a-z]{2,}/i.test(m2.html + m2.text), "brez e-naslovov v telesu (razen morebitnih outly)");
    assert(!m2.html.includes("<script>") && m2.html.includes("&lt;script&gt;") && m2.html.includes("&amp;") && m2.html.includes("&lt;b&gt;"), "HTML naslova in kluba ubezan");
    assert(!/[\r\n]/.test(m2.subject), "zadeva brez prelomov vrstic");

    // --- M2: restart procesa ---
    console.log("\n# M2b: restart procesa");
    await A.ustavi(); await B.ustavi();
    const A2 = zaZagon(PA, { OPOZORILA_MAIL: MAIL_OPOZ });
    assert(await cakajStreznik(PA), "proces A ponovno tece");
    await spi(1800);
    assert(R.vsi.length === 2, "po restartu ni novih maili", R.vsi.length);

    // --- M5: nov dogodek pozneje ---
    console.log("\n# M5: nov dogodek pozneje");
    const B2 = zaZagon(PB, { OPOZORILA_MAIL: MAIL_OPOZ });
    assert(await cakajStreznik(PB), "proces B tece");
    E.nov = await dogodek({ naslov: "Nov Skenmail" });
    assert(await cakaj(() => zaDogodek(R.poslano, "Nov Skenmail").length >= 1), "mail za nov dogodek");
    await spi(1200);
    assert(zaDogodek(R.poslano, "Nov Skenmail").length === 1 && R.poslano.length === 3, "nov dogodek: natanko 1 mail", R.poslano.map((m) => m.subject));

    // --- M6: napake Resenda ---
    console.log("\n# M6: Resend { error }");
    let zavrnjenih = 0;
    R.zavrni = (m) => String(m.subject).includes("Napaka Skenmail") && zavrnjenih++ < 1;   // prvi poskus zavrnjen (422), drugi uspe
    E.napaka = await dogodek({ naslov: "Napaka Skenmail" });
    assert(await cakaj(() => zaDogodek(R.poslano, "Napaka Skenmail").length >= 1, 10000), "po zavrnitvi ponovitev v naslednjem krogu: mail sprejet");
    await spi(1500);
    const ne = (await pool.query("SELECT poskusi, poslano_at FROM sken_opozorila_poslana WHERE event_id=$1", [E.napaka])).rows[0];
    assert(zaDogodek(R.poslano, "Napaka Skenmail").length === 1 && zaDogodek(R.vsi, "Napaka Skenmail").length === 2, "1 zavrnjen + 1 sprejet poskus (2 zahtevka)", [zaDogodek(R.poslano, "Napaka Skenmail").length, zaDogodek(R.vsi, "Napaka Skenmail").length]);
    assert(ne && ne.poskusi === 2 && ne.poslano_at, "evidenca: poskusi 2, poslano_at nastavljen", ne);
    R.zavrni = (m) => String(m.subject).includes("Izcrpan Skenmail");
    E.izcrpan = await dogodek({ naslov: "Izcrpan Skenmail" });
    assert(await cakaj(async () => ((await pool.query("SELECT poskusi FROM sken_opozorila_poslana WHERE event_id=$1", [E.izcrpan])).rows[0] || {}).poskusi === 5, 25000), "trajna napaka: 5 poskusov");
    await spi(2500);
    const iz = (await pool.query("SELECT poskusi, poslano_at FROM sken_opozorila_poslana WHERE event_id=$1", [E.izcrpan])).rows[0];
    assert(iz.poskusi === 5 && iz.poslano_at === null && zaDogodek(R.vsi, "Izcrpan Skenmail").length === 5, "po 5 poskusih ni hitre zanke (naslednji poskus sele po dolgem premoru)", [iz, zaDogodek(R.vsi, "Izcrpan Skenmail").length]);
    assert(/\[sken-opozorilo\] POZOR: mail Martinu za dogodek \d+ ni uspel 5x/.test(A2.log + B2.log), "po izcrpanju POZOR v dnevniku");
    assert(A2.proc.exitCode === null && B2.proc.exitCode === null && (await cakajStreznik(PA)), "procesa po napakah Resenda tecta");
    R.zavrni = () => false;   // Resend spet dela: mail se po dolgem premoru NE izgubi
    assert(await cakaj(() => zaDogodek(R.poslano, "Izcrpan Skenmail").length === 1, 15000), "po izcrpanih poskusih in popravljenem Resendu mail vseeno pride (redka ponovitev)");
    await spi(1500);
    assert(zaDogodek(R.poslano, "Izcrpan Skenmail").length === 1, "in je samo 1");
    await A2.ustavi(); await B2.ustavi();

    // --- M8/M10: en proces z daljsim rokom Resenda ---
    console.log("\n# M8: prestavitev in prenos med posiljanjem");
    const evid = async (id) => (await pool.query("SELECT poskusi, poslano_at, start_at, poslanih FROM sken_opozorila_poslana WHERE event_id=$1", [id])).rows[0];
    const E1 = zaZagon(PE, { OPOZORILA_MAIL: MAIL_OPOZ, GOST_POSTA_TIMEOUT_MS: "1500" });   // premor prevzema vsaj 2500 ms
    assert(await cakajStreznik(PE), "proces E tece");
    R.zakasnitev = (m) => (String(m.subject).includes("Pocasen Prenos") ? 1200 : 0);
    R.naPrejem = (m) => { if (String(m.subject).includes("Pocasen Prenos")) pool.query("INSERT INTO sken_prenosi (event_id, club_id, zadnji_prenos) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING", [E.prenosmed, klub]).catch(() => {}); };
    E.pocasen = await dogodek({ naslov: "Pocasen Prenos Skenmail", start: "NOW() + INTERVAL '20 minutes'" });
    E.prenosmed = await dogodek({ naslov: "Prenosmed Skenmail", start: "NOW() + INTERVAL '40 minutes'" });
    assert(await cakaj(() => zaDogodek(R.poslano, "Pocasen Prenos").length === 1, 10000), "pocasen dogodek: mail pride");
    await spi(1500);
    const pm = await evid(E.prenosmed);
    assert(zaDogodek(R.vsi, "Prenosmed").length === 0, "seznam prenesen med posiljanjem prejsnjega: mail se NE poslje");
    assert(pm && pm.poskusi === 0 && pm.poslano_at === null, "prevzem sprosten brez stetja poskusa", pm);
    const p1 = await evid(E.pocasen);
    R.zakasnitev = () => 0;
    await pool.query("UPDATE sken_opozorila_poslana SET zadnji_mail_at = NOW() - INTERVAL '2 hours' WHERE event_id=$1", [E.pocasen]);   // od zadnjega maila minila > 1 h
    await pool.query("UPDATE events SET start_at = start_at + INTERVAL '90 minutes' WHERE id=$1", [E.pocasen]);   // premik >= 1 h, se vedno v oknu 2 h
    assert(await cakaj(() => zaDogodek(R.poslano, "Pocasen Prenos").length === 2, 8000), "velika prestavitev dolgo po zadnjem mailu: nov mail");
    await spi(1500);
    const p2 = await evid(E.pocasen), nov = (await pool.query("SELECT start_at FROM events WHERE id=$1", [E.pocasen])).rows[0].start_at;
    assert(zaDogodek(R.poslano, "Pocasen Prenos").length === 2, "po prestavitvi natanko 1 dodaten mail (skupaj 2)");
    assert(p2.poskusi === 1 && p2.poslano_at && new Date(p2.start_at).getTime() === new Date(nov).getTime() && new Date(p2.start_at).getTime() !== new Date(p1.start_at).getTime(), "evidenca: nov start_at, poskusi ponastavljen na 1, poslano_at", [p1, p2]);

    console.log("\n# M10: Resend 429, 5xx in molk");
    const rezim = ["429", "500", "molk"];
    R.nacin = (m) => (String(m.subject).includes("Rezim Skenmail") ? rezim.shift() || null : null);
    E.rezim = await dogodek({ naslov: "Rezim Skenmail" });
    assert(await cakaj(() => zaDogodek(R.poslano, "Rezim Skenmail").length >= 1, 25000), "po 429, 5xx in iztekli roku (molk) ponovitev uspe");
    await spi(1500);
    const rz = await evid(E.rezim);
    assert(zaDogodek(R.vsi, "Rezim Skenmail").length === 4 && zaDogodek(R.poslano, "Rezim Skenmail").length === 1, "4 zahtevki, natanko 1 sprejet mail", [zaDogodek(R.vsi, "Rezim Skenmail").length, zaDogodek(R.poslano, "Rezim Skenmail").length]);
    assert(rz.poskusi === 4 && rz.poslano_at, "evidenca: poskusi 4, poslano_at", rz);
    assert(E1.proc.exitCode === null, "proces E po napakah tece");
    R.nacin = () => null;
    await E1.ustavi();

    console.log("\n# M9: pocasen Resend, dva procesa");
    R.zakasnitev = (m) => (String(m.subject).includes("Pocasen Dva") ? 1000 : 0);
    const E2 = zaZagon(PE, { OPOZORILA_MAIL: MAIL_OPOZ, GOST_POSTA_TIMEOUT_MS: "3000", SKEN_OPOZORILO_PREMOR_MS: "300" });   // nastavljen premor 300 ms << odgovor 1000 ms; ucinkovit >= 4000 ms
    const F2 = zaZagon(PF, { OPOZORILA_MAIL: MAIL_OPOZ, GOST_POSTA_TIMEOUT_MS: "3000", SKEN_OPOZORILO_PREMOR_MS: "300" });
    assert(await cakajStreznik(PE) && await cakajStreznik(PF), "procesa E2 in F2 tecta");
    E.pocasen2 = await dogodek({ naslov: "Pocasen Dva Skenmail", start: "NOW() + INTERVAL '25 minutes'" });
    assert(await cakaj(() => zaDogodek(R.poslano, "Pocasen Dva").length >= 1, 8000), "pocasen mail pride");
    await spi(5500);   // vec krogov obeh procesov, tudi po preteku nastavljenega premora
    assert(zaDogodek(R.vsi, "Pocasen Dva").length === 1 && zaDogodek(R.poslano, "Pocasen Dva").length === 1, "natanko 1 mail (ni dvojnika med pocasnim posiljanjem)", [zaDogodek(R.vsi, "Pocasen Dva").length, zaDogodek(R.poslano, "Pocasen Dva").length]);
    R.zakasnitev = () => 0;
    await E2.ustavi(); await F2.ustavi();

    // --- M11-M13: premiki, trda meja ---
    console.log("\n# M11-M13: premiki in trda meja");
    const E3 = zaZagon(PE, { OPOZORILA_MAIL: MAIL_OPOZ });
    assert(await cakajStreznik(PE), "proces E3 tece");
    const stMailov = (n) => zaDogodek(R.poslano, n).length;
    E.min = await dogodek({ naslov: "Minutni Skenmail", start: "NOW() + INTERVAL '30 minutes'" });
    assert(await cakaj(() => stMailov("Minutni Skenmail") === 1, 8000), "M11: prvi mail");
    for (let i = 0; i < 10; i++) { await pool.query("UPDATE events SET start_at = start_at + INTERVAL '1 minute' WHERE id=$1", [E.min]); await spi(400); }
    const mn = await evid(E.min), mnEv = (await pool.query("SELECT start_at FROM events WHERE id=$1", [E.min])).rows[0].start_at;
    assert(stMailov("Minutni Skenmail") === 1 && zaDogodek(R.vsi, "Minutni Skenmail").length === 1, "M11: 10 premikov po 1 min -> se vedno 1 mail", stMailov("Minutni Skenmail"));
    assert(new Date(mn.start_at).getTime() === new Date(mnEv).getTime(), "M11: start_at v evidenci sledi dogodku (brez novega maila)");
    E.velik = await dogodek({ naslov: "Velik Skenmail", start: "NOW() + INTERVAL '10 minutes'" });
    assert(await cakaj(() => stMailov("Velik Skenmail") === 1, 8000), "M12: prvi mail");
    await pool.query("UPDATE sken_opozorila_poslana SET zadnji_mail_at = NOW() - INTERVAL '2 hours' WHERE event_id=$1", [E.velik]);
    await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '90 minutes' WHERE id=$1", [E.velik]);
    assert(await cakaj(() => stMailov("Velik Skenmail") === 2, 8000), "M12: premik >= 1 h po > 1 h od maila -> 2. mail");
    await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '10 minutes' WHERE id=$1", [E.velik]);   // takoj spet velik premik, a manj kot 1 h od zadnjega maila
    await spi(1500);
    assert(stMailov("Velik Skenmail") === 2, "M12: velik premik < 1 h po mailu -> brez novega maila", stMailov("Velik Skenmail"));
    E.meja = await dogodek({ naslov: "Meja Skenmail", start: "NOW() + INTERVAL '10 minutes'" });
    assert(await cakaj(() => stMailov("Meja Skenmail") === 1, 8000), "M13: prvi mail");
    for (let i = 0; i < 5; i++) {
      await pool.query("UPDATE sken_opozorila_poslana SET zadnji_mail_at = NOW() - INTERVAL '2 hours' WHERE event_id=$1", [E.meja]);
      await pool.query(`UPDATE events SET start_at = NOW() + INTERVAL '${i % 2 === 0 ? 90 : 10} minutes' WHERE id=$1`, [E.meja]);
      await spi(1100);
    }
    const mj = await evid(E.meja);
    assert(stMailov("Meja Skenmail") === 3, "M13: 5 velikih premikov -> skupaj najvec 3 maili (trda meja)", stMailov("Meja Skenmail"));
    assert((await pool.query("SELECT poslanih FROM sken_opozorila_poslana WHERE event_id=$1", [E.meja])).rows[0].poslanih === 3, "M13: poslanih = 3");
    assert(/\[sken-opozorilo\] POZOR: dogodek \d+: dosezena trda meja 3 poslanih mailov/.test(E3.log), "M13: POZOR ob dosezeni meji");
    await E3.ustavi();

    console.log("\n# M14: pocasen Resend, ki sprejme po roku");
    const E4 = zaZagon(PE, { OPOZORILA_MAIL: MAIL_OPOZ, GOST_POSTA_TIMEOUT_MS: "400", SKEN_OPOZORILO_DOLGI_PREMOR_MS: "1000" });   // ucinkovit premor 1400 ms
    R.zakasnitev = (m) => (String(m.subject).includes("Ves Dan") ? 800 : 0);
    assert(await cakajStreznik(PE), "proces E4 tece");
    E.vesdan = await dogodek({ naslov: "Ves Dan Skenmail", start: "NOW() + INTERVAL '35 minutes'" });
    assert(await cakaj(() => zaDogodek(R.vsi, "Ves Dan").length >= 10, 40000), "M14: doseženih 10 zahtevkov");
    await spi(4500);
    const vd = await evid(E.vesdan), vdn = (await pool.query("SELECT poskusi_skupaj, poslanih FROM sken_opozorila_poslana WHERE event_id=$1", [E.vesdan])).rows[0];
    assert(zaDogodek(R.vsi, "Ves Dan").length === 10, "M14: natanko 10 zahtevkov in ne vec (trda meja)", zaDogodek(R.vsi, "Ves Dan").length);
    assert(vdn.poskusi_skupaj === 10 && vdn.poslanih === 0, "M14: poskusi_skupaj 10, poslanih 0 (nas odjemalec je vsak poskus steje za neuspel)", vdn);
    assert(/\[sken-opozorilo\] POZOR: dogodek \d+: dosezena trda meja 10 poskusov/.test(E4.log), "M14: POZOR ob dosezeni meji");
    await E4.ustavi();
    R.zakasnitev = () => 0;

    console.log("\n# M15: prestavitev med pocasnim posiljanjem");
    let dirka = 0;
    R.zakasnitev = (m) => (String(m.subject).includes("Dirka") && ++dirka === 1 ? 1500 : 0);
    let premaknjen = false;
    R.naPrejem = (m) => { if (String(m.subject).includes("Dirka") && !premaknjen) { premaknjen = true; pool.query("UPDATE events SET start_at = start_at + INTERVAL '1 minute' WHERE id=$1", [E.dirka]).catch(() => {}); } };
    const E5 = zaZagon(PE, { OPOZORILA_MAIL: MAIL_OPOZ, GOST_POSTA_TIMEOUT_MS: "3000", SKEN_OPOZORILO_PREMOR_MS: "300" });
    const F5 = zaZagon(PF, { OPOZORILA_MAIL: MAIL_OPOZ, GOST_POSTA_TIMEOUT_MS: "3000", SKEN_OPOZORILO_PREMOR_MS: "300" });
    assert(await cakajStreznik(PE) && await cakajStreznik(PF), "procesa E5 in F5 tecta");
    E.dirka = await dogodek({ naslov: "Dirka Skenmail", start: "NOW() + INTERVAL '45 minutes'" });
    assert(await cakaj(async () => ((await evid(E.dirka)) || {}).poslanih === 1, 10000), "M15: prvi (pocasen) mail je koncan");
    const dk = await evid(E.dirka), dkEv = (await pool.query("SELECT start_at FROM events WHERE id=$1", [E.dirka])).rows[0].start_at;
    assert(new Date(dk.start_at).getTime() === new Date(dkEv).getTime() && dk.poslano_at === null, "M15: stari mail NE oznaci prestavljenega termina kot poslanega (poslano_at ostane NULL)", dk);
    assert(await cakaj(() => stMailov("Dirka Skenmail") === 2, 12000), "M15: mail za nov termin pride naknadno");
    await spi(500);
    const prvi = zaDogodek(R.poslano, "Dirka")[0].text, drugi = zaDogodek(R.poslano, "Dirka")[1].text;
    assert(prvi !== drugi, "M15: drugi mail ima nov cas zacetka");
    assert((await evid(E.dirka)).poslano_at, "M15: po mailu za nov termin je poslano_at nastavljen");
    R.zakasnitev = () => 0; R.naPrejem = () => {};
    await E5.ustavi(); await F5.ustavi();

    // --- M7: brez prejemnika / samo AGENT_NUJNO_MAIL ---
    console.log("\n# M7: brez prejemnika");
    await pool.query("TRUNCATE sken_opozorila_poslana");
    const prej = R.vsi.length;
    const C = zaZagon(PC, {});
    assert(await cakajStreznik(PC), "proces C (brez OPOZORILA_MAIL in AGENT_NUJNO_MAIL) tece");
    assert(await cakaj(() => /\[sken-opozorilo\] POZOR: \d+ dogodkov/.test(C.log), 4000), "POZOR v dnevniku (brez prejemnika)", C.log.slice(-300));
    await spi(1000);
    assert(R.vsi.length === prej, "0 mailov brez prejemnika", R.vsi.length - prej);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM sken_opozorila_poslana")).rows[0].n === 0, "brez maila ni vpisa v evidenco (po nastavitvi naslova mail se pride)");
    assert(C.proc.exitCode === null && (await fetch(`http://127.0.0.1:${PC}/`).then((r) => r.status < 500, () => false)), "proces ne pade");
    assert((C.log.match(/\[sken-opozorilo\] POZOR: \d+ dogodkov/g) || []).length === 1, "POZOR najvec 1x (pozorRedko)", (C.log.match(/\[sken-opozorilo\] POZOR/g) || []).length);
    await C.ustavi();
    const H = zaZagon(PH, { OPOZORILA_MAIL: MAIL_OPOZ, RESEND_API_KEY: "" });
    assert(await cakajStreznik(PH), "proces H (prejemnik, a brez RESEND_API_KEY) tece");
    assert(await cakaj(() => /\[sken-opozorilo\] POZOR: \d+ dogodkov/.test(H.log), 4000), "brez Resenda: POZOR v dnevniku", H.log.slice(-300));
    await spi(800);
    assert(R.vsi.length === prej && (await pool.query("SELECT COUNT(*)::int AS n FROM sken_opozorila_poslana")).rows[0].n === 0, "brez Resenda: 0 mailov in brez vpisa v evidenco");
    assert(H.proc.exitCode === null, "brez Resenda: proces ne pade");
    await H.ustavi();
    const D = zaZagon(PD, { AGENT_NUJNO_MAIL: MAIL_NUJNO });
    assert(await cakajStreznik(PD), "proces D (samo AGENT_NUJNO_MAIL) tece");
    assert(await cakaj(() => R.poslano.some((m) => prejemniki(m).includes(MAIL_NUJNO)), 6000), "rezerva: mail gre na AGENT_NUJNO_MAIL");
    await D.ustavi();
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
  } finally {
    for (const p of procesi) await p.ustavi();
    jwksServer.close(); if (resendServer.closeAllConnections) resendServer.closeAllConnections(); resendServer.close();
    await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
