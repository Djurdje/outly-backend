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
 *  M7  brez prejemnika: 0 mailov, `[sken-opozorilo] POZOR`, proces zivi; samo AGENT_NUJNO_MAIL -> mail gre tja
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 6930, RESEND_PORT = 6931, PA = 6932, PB = 6933, PC = 6934, PD = 6935;
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

// Lazni Resend: R.vsi = vsi zahtevki, R.poslano = sprejeti; R.zavrni(m) -> true = 422 (dokazana zavrnitev PRED obdelavo)
const R = { vsi: [], poslano: [], zavrni: () => false };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", (x) => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      const m = JSON.parse(d); R.vsi.push(m);
      if (R.zavrni(m)) { res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub: zavrnjeno", statusCode: 422 })); }
      R.poslano.push(m); res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + R.poslano.length }));
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
    RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", GOST_POSTA_TIMEOUT_MS: "1500",
    ADMIN_NADZOR_PREDPOMNILNIK_MS: "0", REZERVACIJE_CISCENJE_MS: "0", OPOZORILA_MAIL: "", AGENT_NUJNO_MAIL: "", SKEN_OPOZORILO_MS: "300", SKEN_OPOZORILO_PREMOR_MS: "500", ...okolje },
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
    assert(await cakaj(async () => ((await pool.query("SELECT poskusi FROM sken_opozorila_poslana WHERE event_id=$1", [E.izcrpan])).rows[0] || {}).poskusi === 5, 15000), "trajna napaka: 5 poskusov");
    await spi(2500);
    const iz = (await pool.query("SELECT poskusi, poslano_at FROM sken_opozorila_poslana WHERE event_id=$1", [E.izcrpan])).rows[0];
    assert(iz.poskusi === 5 && iz.poslano_at === null && zaDogodek(R.vsi, "Izcrpan Skenmail").length === 5, "po 5 poskusih se ustavi (brez neskoncne zanke)", [iz, zaDogodek(R.vsi, "Izcrpan Skenmail").length]);
    assert(/\[sken-opozorilo\] POZOR: mail Martinu za dogodek \d+ ni uspel 5x/.test(A2.log + B2.log), "po izcrpanju POZOR v dnevniku");
    assert(A2.proc.exitCode === null && B2.proc.exitCode === null && (await cakajStreznik(PA)), "procesa po napakah Resenda tecta");
    R.zavrni = () => false;
    await A2.ustavi(); await B2.ustavi();

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
    const D = zaZagon(PD, { AGENT_NUJNO_MAIL: MAIL_NUJNO });
    assert(await cakajStreznik(PD), "proces D (samo AGENT_NUJNO_MAIL) tece");
    assert(await cakaj(() => R.poslano.some((m) => prejemniki(m).includes(MAIL_NUJNO)), 6000), "rezerva: mail gre na AGENT_NUJNO_MAIL");
    await D.ustavi();
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
  } finally {
    for (const p of procesi) await p.ustavi();
    jwksServer.close(); resendServer.close();
    await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
