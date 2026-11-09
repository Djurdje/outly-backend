#!/usr/bin/env node
/**
 * Alarmi iz procesa (#403, I70): srcni utrip delavcev (delavci.js), GET /healthz/opozorila, redki POZOR, serije pospravljalca Stripa.
 * Zagon (PG16, prazna baza z migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_alarmi.js
 *
 *   U  enota delavci.js (lazna ura): zaostanek po max(3 x perioda, rok), zagonski zamik, rokMinMs, rok NE sprosti zastavice (le POZOR 1x),
 *      izklopljen delavec (perioda 0) se ne registrira, pozorRedko 1x na 10 min, uspeh/bilUspeh
 *   A  cista baza: GET /healthz/opozorila -> 200 { ok: true } (SAMO ta kljuc), Cache-Control no-store; rezultat velja OPOZORILA_ZDRAVJE_VELJA_MS (predpomnjen)
 *   B  pending narocilo starejse od 60 min -> 503 + opozorilo narocila_visijo (rdece, samo stevilo); mlajse ne; placilo v obdelavi ne (oranzno >14 dni, brez 503);
 *      gost_vstopnice_neposlane (rdece) -> 503; poslovno rdece opozorilo (racun_napaka) je v panelu, a /healthz/opozorila ostane 200
 *   C  obvisel delavec (racuni_pospravi, zaklep SHARE ROW EXCLUSIVE na racuni blokira INSERT) -> 503, POZOR; obvisel krog NE sprozi novih (1 cakajoca seja); po sprostitvi spet 200
 *   D  napacen podpis webhooka -> POZOR 1x v oknu brez veljavnega podpisa, brez glave podpisa; po veljavnem podpisu v oknu ni POZOR (smetje)
 *   E  pospravljalec Stripa obdela 120 kandidatov v ENEM krogu (serije po 50); ob Stripovi omejitvi hitrosti (429) krog preneha
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool, Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 6912, STRIPE_PORT = 6913;
const KID = "test-kid-alarmi";
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: new Date().toISOString() })); } catch { return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});
const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
function zeton(email, sub) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${JWKS_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now,
    user_metadata: { email_verified: true, username: email.split("@")[0].replace(/[^a-z0-9_]/gi, "") } });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}

// lazni Stripe: vsaka seja je potekla (-> narocilo cancelled); steje GET-e
const S = { branja: 0 };
const stripeServer = http.createServer((req, res) => {
  req.resume();
  const m = req.url.split("?")[0].match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/);
  if (m && S.rezim429) { S.branja++; res.writeHead(429, { "content-type": "application/json", "request-id": "req_test" }); return res.end(JSON.stringify({ error: { type: "rate_limit_error", message: "Too many requests" } })); }
  res.writeHead(m ? 200 : 404, { "content-type": "application/json", "request-id": "req_test" });
  if (!m) return res.end(JSON.stringify({ error: { type: "invalid_request_error", message: "neznana pot" } }));
  S.branja++;
  res.end(JSON.stringify({ id: m[1], object: "checkout.session", status: "expired", payment_status: "unpaid", payment_intent: null, metadata: { order_id: m[1].slice(3) } }));
});

async function zazeni(port, dodatniEnv = {}) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, REZERVACIJE_CISCENJE_MS: "0", PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`,
    RESEND_API_KEY: "", QR_SECRET: "test", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0", STRIPE_SECRET_KEY: "", ...dodatniEnv }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 100; i++) { try { await fetch(`http://127.0.0.1:${port}/`); break; } catch { await spi(100); } }
  return { log: () => log, ustavi: () => new Promise((r) => { if (srv.exitCode !== null) return r(); srv.once("exit", r); srv.kill(); }) };
}
async function klic(port, pot, opcije = {}) {
  try {
    const r = await fetch(`http://127.0.0.1:${port}${pot}`, { method: opcije.metoda || "GET", headers: opcije.glave || {}, body: opcije.telo, signal: AbortSignal.timeout(15000) });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j, cache: r.headers.get("cache-control") };
  } catch (e) { return { status: "visi", body: String(e.message) }; }
}
const zdravje = (port) => klic(port, "/healthz/opozorila");

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE stripe_uskladitve, racuni, vracila, spori, admin_dejanja, agent_zetoni, omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  await new Promise((r) => stripeServer.listen(STRIPE_PORT, r));

  // ------------------------------------------------------------ U
  console.log("# U: delavci.js (lazna ura)");
  {
    const { ustvari } = require("../delavci");
    let t = 1000000; const zapisi = [];
    const d = ustvari({ zdaj: () => t, log: { error: (s) => zapisi.push(s) }, env: {} });
    const h = d.registriraj("a", { periodaMs: 10000, zamikMs: 5000 });
    assert(d.zaostali().length === 0, "pravkar zagnan delavec ni zaostal");
    t += 5 * 60 * 1000; assert(d.zaostali().length === 0, "do roka (5 min) od zagona + zamik (5 s) ni zaostal");
    t += 5000 + 2; assert(d.zaostali().join() === "a", "brez kroga cez max(3 x perioda, rok) -> zaostal");
    const k = h.zacetek(); assert(d.zaostali().length === 1, "zacetek kroga ne pomeni utripa");
    k.konec(); assert(d.zaostali().length === 0, "konec kroga = utrip, ni vec zaostal");
    // izklopljen
    const h0 = d.registriraj("izklopljen", { periodaMs: 0 }); h0.zacetek().konec();
    t += 10 * 24 * 3600 * 1000; assert(!d.stanje().some((x) => x.ime === "izklopljen"), "delavec s periodo 0 se ne registrira");
    // rok: samo POZOR, zastavice ni kaj sprostiti (pravi casovnik: kratek rok prek env)
    const d2 = ustvari({ log: { error: (s) => zapisi.push(s) }, env: { DELAVCI_ROK_MS: "80" } });
    const h2 = d2.registriraj("b", { periodaMs: 20 });
    const k1 = h2.zacetek(); await spi(300);
    assert(zapisi.filter((s) => /POZOR.*delavec b/.test(s)).length === 1, "POZOR ob izteku roka (1x)", zapisi);
    assert(h2.zacetek.length === 0 && /ne tece/.test(zapisi.join()), "zacetek() nima sprostitve zastavice; sporocilo pove, da naslednji krog ne tece");
    k1.konec();
    assert(d.rokZa(1000, 20 * 60 * 1000) === 20 * 60 * 1000 && d.rokZa(1000) === 5 * 60 * 1000 && d.rokZa(10 * 60 * 1000) === 30 * 60 * 1000, "rok = max(rokMinMs ali 5 min, 3 x perioda)");
    d.uspeh("x"); assert(d.bilUspeh("x", 1000) && !d.bilUspeh("y", 1000), "uspeh/bilUspeh");
    t += 2000; assert(!d.bilUspeh("x", 1000), "bilUspeh po izteku okna false");
    let n = 0; const dr = ustvari({ zdaj: () => t, log: { error: () => { n++; } }, env: {} });
    dr.pozorRedko("x", "a"); dr.pozorRedko("x", "a"); t += 9 * 60 * 1000; dr.pozorRedko("x", "a"); t += 2 * 60 * 1000; dr.pozorRedko("x", "a"); dr.pozorRedko("y", "a");
    assert(n === 3, "pozorRedko: 1x na 10 min na kljuc (x, x po 11 min, y)", n);
  }

  // ------------------------------------------------------------ A, B
  console.log("# A/B: /healthz/opozorila na cisti bazi in z visecim narocilom");
  const P1 = 6911;
  let b = await zazeni(P1, { OPOZORILA_ZDRAVJE_VELJA_MS: "300" });
  try {
    let r = await zdravje(P1);
    assert(r.status === 200 && r.body && r.body.ok === true, "cista baza -> 200 { ok: true }", r);
    assert(r.body && Object.keys(r.body).join() === "ok", "odgovor ima SAMO kljuc ok", r.body);
    assert(/no-store/.test(r.cache || ""), "Cache-Control: no-store", r.cache);

    const u = (await pool.query("INSERT INTO users (email, username, role) VALUES ('lastnik@x.si','lastnik','business') RETURNING id")).rows[0].id;
    const a = (await pool.query("INSERT INTO users (email, username, role) VALUES ('admin@outly.si','adminx','admin') RETURNING id")).rows[0];
    const klub = (await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Klub A', 'Ljubljana') RETURNING id", [u])).rows[0].id;
    const dog = (await pool.query("INSERT INTO events (club_id, title, status, start_at) VALUES ($1, 'Osnutek', 'draft', NOW() + INTERVAL '3 days') RETURNING id", [klub])).rows[0].id;
    const narocilo = (ref, min, polja = {}) => pool.query(
      `INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, created_at, stripe_checkout_session_id, checkout_url, guest_email, paid_at, guest_terms_version, guest_terms_accepted_at, stripe_payment_intent_id, guest_mail_attempts)
       VALUES ($1, $2, $3, 1, 1000, 1000, $5, 'k@x.si', NOW() - ($4::int * INTERVAL '1 minute'), $6, $7, $8, CASE WHEN $5 IN ('paid', 'partially_refunded') THEN NOW() - ($4::int * INTERVAL '1 minute') ELSE NULL END, CASE WHEN $8::text IS NULL THEN NULL ELSE '1' END, CASE WHEN $8::text IS NULL THEN NULL ELSE NOW() END, $9, $10)`,
      [ref, dog, klub, min, polja.status || "pending", polja.seja || null, polja.url === undefined ? null : polja.url, polja.gost || null, polja.pi || null, polja.poskusi || 0]);
    const pocakaj = () => spi(400);
    await pool.query("UPDATE users SET supabase_uid = $2 WHERE id = $1", [a.id, "00000000-0000-4000-8000-000000000001"]);
    const T = zeton("admin@outly.si", "00000000-0000-4000-8000-000000000001");
    await klic(P1, "/me", { glave: { authorization: "Bearer " + T } });
    const panel = async () => (await klic(P1, "/admin/api/opozorila", { glave: { authorization: "Bearer " + T } })).body;
    const vrste = (o) => (o && o.items ? o.items.map((x) => x.vrsta) : []);
    await narocilo("ALARM-MLADO", 30);
    await narocilo("ALARM-50", 50);
    await pocakaj();
    r = await zdravje(P1);
    assert(r.status === 200 && r.body.ok === true, "pending narocilo staro 30 in 50 min ne sprozi alarma (prag 60 min)", r);
    // placilo v obdelavi: seja obstaja, checkout_url NULL (oznaciVObdelavi) - tudi 2 uri staro ni alarm
    await narocilo("ALARM-OBDELAVA", 120, { seja: "cs_obdelava1" });
    await pocakaj();
    r = await zdravje(P1);
    assert(r.status === 200, "placilo v obdelavi (checkout_url NULL ob seji) ni narocila_visijo", r);
    assert(!vrste(await panel()).includes("narocila_visijo"), "panel: brez narocila_visijo za placilo v obdelavi");
    await narocilo("ALARM-OBDELAVA-DOLGO", 15 * 24 * 60, { seja: "cs_obdelava2" });
    await pocakaj();
    const p14 = await panel();
    r = await zdravje(P1);
    assert(vrste(p14).includes("placilo_v_obdelavi_dolgo") && p14.items.find((x) => x.vrsta === "placilo_v_obdelavi_dolgo").resnost === "oranzno", "placilo v obdelavi > 14 dni: ORANZNO opozorilo", vrste(p14));
    assert(r.status === 200, "oranzno opozorilo ne da 503", r);
    // predpomnjenje: sprememba znotraj okna ne vpliva (tu okno 300 ms)
    await narocilo("ALARM-STARO", 70);
    r = await zdravje(P1);
    assert(r.status === 200, "rezultat je predpomnjen (znotraj OPOZORILA_ZDRAVJE_VELJA_MS ostane prejsnji)", r);
    await pocakaj();
    r = await zdravje(P1);
    assert(r.status === 503 && r.body.ok === false && Object.keys(r.body).join() === "ok", "pending starejse od 60 min -> 503 { ok: false }", r);
    const op = await panel();
    const vr = op && op.items ? op.items.filter((x) => x.vrsta === "narocila_visijo") : [];
    assert(vr.length === 1 && vr[0].resnost === "rdece", "opozorilo narocila_visijo (rdece)", op);
    assert(vr.length && /^1 /.test(vr[0].besedilo) && !/ALARM-|k@x\.si/.test(JSON.stringify(vr[0])), "samo stevilo, brez reference in kupca", vr);
    await pool.query("UPDATE orders SET status = 'cancelled' WHERE public_ref = 'ALARM-STARO'");
    await pocakaj();
    r = await zdravje(P1);
    assert(r.status === 200 && r.body.ok === true, "po odpravi spet 200", r);
    // gost: placano narocilo, mail z vstopnicami ni poslan 30+ min (brez delavca: RESEND_API_KEY ""; pospravljalec ga tu ne dotika)
    const gostPreizkus = async (ref, n, polja, oc503) => {
      for (let k = 0; k < n; k++) await narocilo(`${ref}-${k}`, 40, { status: "paid", gost: `gost${k}@primer.si`, ...polja, pi: polja.pi ? `${polja.pi}${k}` : undefined });
      await pocakaj();
      const rr = await zdravje(P1), pp = await panel();
      assert(rr.status === (oc503 ? 503 : 200), `${ref} x${n}: javni alarm ${oc503 ? "503" : "200"}`, { rr, v: vrste(pp) });
      await pool.query("DELETE FROM orders WHERE public_ref LIKE $1", [ref + "-%"]);
      await pocakaj();
      return pp;
    };
    const ost = (pp, vrsta) => pp.items.find((x) => x.vrsta === vrsta);
    let pg = await gostPreizkus("ALARM-G1", 1, {}, false);
    assert(ost(pg, "gost_vstopnica_neposlana") && ost(pg, "gost_vstopnica_neposlana").resnost === "oranzno" && !vrste(pg).includes("gost_vstopnice_neposlane"), "natanko 1 gost brez maila: ORANZNO gost_vstopnica_neposlana, ne rdece", vrste(pg));
    pg = await gostPreizkus("ALARM-G2", 2, {}, true);
    assert(ost(pg, "gost_vstopnice_neposlane") && ost(pg, "gost_vstopnice_neposlane").resnost === "rdece", "2 gosta brez maila (vzorec izpada): RDECE gost_vstopnice_neposlane + 503", vrste(pg));
    assert(!/gost\d@primer|ALARM-G2/.test(JSON.stringify(pg)), "opozorilo gosta brez e-naslova in reference");
    pg = await gostPreizkus("ALARM-GD", 2, { status: "partially_refunded" }, false);
    assert(!vrste(pg).some((v) => /^gost_/.test(v)), "delno vrnjeno (delavec ga ne posilja): ni v alarmu", vrste(pg));
    pg = await gostPreizkus("ALARM-GI", 2, { poskusi: 8 }, false);
    assert(ost(pg, "gost_vstopnice_izcrpane") && ost(pg, "gost_vstopnice_izcrpane").resnost === "oranzno" && !vrste(pg).includes("gost_vstopnice_neposlane"), "izcrpani poskusi: ORANZNO gost_vstopnice_izcrpane v panelu, 200", vrste(pg));
    pg = await gostPreizkus("ALARM-GT", 2, { pi: "test_pi_alarm" }, false);
    assert(!vrste(pg).some((v) => /^gost_/.test(v)), "testni promet: nobenega gost_ opozorila", vrste(pg));
    await narocilo("ALARM-GOST", 40, { status: "paid", gost: "gost@primer.si" });
    await pool.query("UPDATE orders SET guest_mail_sent_at = NOW() WHERE public_ref = 'ALARM-GOST'");
    await pocakaj();
    r = await zdravje(P1);
    assert(r.status === 200, "po poslanem mailu spet 200", r);
    // poslovno rdece opozorilo (racun_napaka) je v panelu, a javni alarm ostane 200
    const brez = new Client({ connectionString: DB }); await brez.connect(); await brez.query("SET session_replication_role = replica");
    const oid = (await pool.query("SELECT id FROM orders WHERE public_ref = 'ALARM-GOST'")).rows[0].id;
    const rid = (await brez.query("INSERT INTO racuni (order_id, vrsta, znesek_cents, stanje) VALUES ($1, 'racun', 1000, 'caka') RETURNING id", [oid])).rows[0].id;
    await brez.query("UPDATE racuni SET stanje = 'napaka' WHERE id = $1", [rid]); await brez.end();
    await pocakaj();
    const pr = await panel();
    r = await zdravje(P1);
    assert(vrste(pr).includes("racun_napaka") && pr.stevci.rdece > 0, "panel ima poslovno rdece opozorilo (racun_napaka)", pr);
    assert(r.status === 200 && r.body.ok === true, "poslovno rdece opozorilo NE da 503 na /healthz/opozorila", r);
  } finally { await b.ustavi(); }

  // ------------------------------------------------------------ C
  console.log("# C: obvisel delavec");
  const P2 = 6914;
  b = await zazeni(P2, { OPOZORILA_ZDRAVJE_VELJA_MS: "300", RACUNI_POSPRAVI_MS: "1000", RACUNI_POSPRAVI_ZAMIK_MS: "0", DELAVCI_ROK_MS: "2000" });
  const drzi = await pool.connect();
  try {
    await spi(2500);
    let r = await zdravje(P2);
    assert(r.status === 200 && r.body.ok === true, "delavec, ki redno koncuje kroge -> 200", r);
    await drzi.query("BEGIN; LOCK TABLE racuni IN SHARE ROW EXCLUSIVE MODE");   // blokira INSERT pospravljalca, branje opozoril (ACCESS SHARE) ostane
    await spi(5500);
    r = await zdravje(P2);
    assert(r.status === 503 && r.body.ok === false, "obvisel krog delavca -> 503 { ok: false }", r);
    assert(/POZOR.*racuni_pospravi/.test(b.log()), "POZOR za delavca v dnevniku", b.log().slice(-400));
    const cakajoce = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()")).rows[0].n;
    assert(await cakajoce() === 1, "obvisel krog NE sprozi novih krogov: po 5 s (5 period) je natanko 1 sejo na zaklepu (brez zombijev)", await cakajoce());
    await drzi.query("ROLLBACK");
    await spi(2500);
    r = await zdravje(P2);
    assert(r.status === 200 && r.body.ok === true, "po sprostitvi zaklepa delavec spet koncuje kroge -> 200", r);
  } finally { drzi.release(); await b.ustavi(); }

  // ------------------------------------------------------------ D, E
  console.log("# D/E: podpis webhooka in serije pospravljalca");
  const P3 = 6915;
  await pool.query("TRUNCATE orders, events, clubs, users RESTART IDENTITY CASCADE");
  const u3 = (await pool.query("INSERT INTO users (email, username, role) VALUES ('l@x.si','l','business') RETURNING id")).rows[0].id;
  const k3 = (await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Klub B', 'Ljubljana') RETURNING id", [u3])).rows[0].id;
  const d3 = (await pool.query("INSERT INTO events (club_id, title, status, start_at) VALUES ($1, 'Osnutek', 'draft', NOW() + INTERVAL '3 days') RETURNING id", [k3])).rows[0].id;
  const N = 120;
  await pool.query(
    `INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, created_at, stripe_checkout_session_id, checkout_expires_at, checkout_url)
     SELECT 'POSP-' || g, $1, $2, 1, 1000, 1000, 'pending', 'k@x.si', NOW() - INTERVAL '1 hour', 'cs_' || (SELECT COALESCE(MAX(id), 0) FROM orders) || g, NOW() - INTERVAL '20 minutes', 'https://checkout.test/x'
       FROM generate_series(1, $3) g`, [d3, k3, N]);
  b = await zazeni(P3, { STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_CONNECT_WEBHOOK_SECRET: "whsec_connect", STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_POSPRAVI_MS: "3000", STRIPE_PODPIS_OKNO_MS: "1500" });
  try {
    const napacna = { "content-type": "application/json", "stripe-signature": "t=1700000000,v1=00ff00ffnapacen" };
    const Stripe = require("stripe");
    const telo = JSON.stringify({ id: "evt_veljaven1", object: "event", type: "ping.test", livemode: false, data: { object: {} } });
    const veljavna = { "content-type": "application/json", "stripe-signature": new Stripe("sk_test_lokalno").webhooks.generateTestHeaderString({ payload: telo, secret: "whsec_test" }) };
    const poz = (ime) => b.log().split("\n").filter((l) => new RegExp(`POZOR.*Stripe webhook \\(${ime}\\).*podpis`, "i").test(l)).length;
    await spi(1800);   // okno STRIPE_PODPIS_OKNO_MS (1500 ms) od zagona je mimo
    let w = await klic(P3, "/stripe/webhook", { metoda: "POST", glave: veljavna, telo });
    assert(w.status === 200, "veljaven podpis -> 200", w);
    w = await klic(P3, "/stripe/webhook", { metoda: "POST", glave: napacna, telo: "{\"id\":\"evt_1\"}" });
    assert(w.status === 400 && poz("platformni") === 0, "napacen podpis TIK po veljavnem platformnem: brez POZOR za platformni (smetje z interneta)", { w, poz: poz("platformni") });
    assert(poz("connect") === 1, "connect endpoint v oknu ni imel nobenega veljavnega podpisa -> POZOR (platformni uspeh ga ne krije)", poz("connect"));
    assert(!/POZOR.*whsec_/.test(b.log()), "dnevnik ne razkrije skrivnosti");
    await spi(1800);   // okno platformnega brez veljavnega podpisa
    for (let i = 0; i < 3; i++) await klic(P3, "/stripe/webhook", { metoda: "POST", glave: napacna, telo: "{\"id\":\"evt_1\"}" });
    assert(poz("platformni") === 1, "napacen podpis brez veljavnega v oknu: POZOR natanko 1x (3 klici)", poz("platformni"));
    assert(poz("connect") === 1, "connect POZOR se ne ponavlja (najvec 1x na 10 min)", poz("connect"));
    assert(!/napacen00|00ff00ff|evt_1/.test(b.log()), "dnevnik ne vsebuje glave podpisa ne telesa");
    // E: po prvem teku (3 s) je ob staremu LIMIT 50 obdelanih 50; nova koda ponavlja serije
    await spi(5000);
    const n = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE status = 'cancelled' AND public_ref LIKE 'POSP-%'")).rows[0].n;
    assert(n === N, `en krog obdela vse kandidate (${N}), ne samo 50`, { n, branja: S.branja });
    // L1: Stripova omejitev hitrosti (429) prekine preostanek kroga
    await pool.query(
      `INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, created_at, stripe_checkout_session_id, checkout_expires_at, checkout_url)
       SELECT 'OMEJ-' || g, $1, $2, 1, 1000, 1000, 'pending', 'k@x.si', NOW() - INTERVAL '1 hour', 'cs_9' || g, NOW() - INTERVAL '20 minutes', 'https://checkout.test/x' FROM generate_series(1, 30) g`, [d3, k3]);
    S.rezim429 = true; const pred = S.branja;
    await spi(3500);   // en tek pospravljalec (perioda 3 s)
    const razlika = S.branja - pred;
    assert(razlika >= 1 && razlika <= 6, `ob 429 krog preneha po prvem narocilu (zahtevkov ${razlika}, brez prekinitve bi jih bilo ≥ 30)`, razlika);
  } finally { await b.ustavi(); }

  // ------------------------------------------------------------ F: pravi pospravljalec gostove poste z lazno Resend
  console.log("# F: pospravljalec gostove poste (lazni Resend) in alarm");
  const P4 = 6916, RESEND_PORT = 6917;
  await pool.query("TRUNCATE tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  const R = { napaka: true, poslano: [] };
  const resendServer = http.createServer((req, res) => {
    let d = ""; req.on("data", (x) => d += x);
    req.on("end", () => {
      if (R.napaka) { res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub", statusCode: 422 })); }
      try { R.poslano.push(JSON.parse(d)); } catch { /* ni JSON */ }
      res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ id: "mail_" + R.poslano.length }));
    });
  });
  await new Promise((r) => resendServer.listen(RESEND_PORT, r));
  const uF = (await pool.query("INSERT INTO users (email, username, role) VALUES ('lf@x.si','lf','business') RETURNING id")).rows[0].id;
  const kF = (await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Klub F', 'Ljubljana') RETURNING id", [uF])).rows[0].id;
  const dF = (await pool.query("INSERT INTO events (club_id, title, status, start_at, end_at, ticket_price_cents, capacity, min_age) VALUES ($1, 'Gost F', 'published', NOW() + INTERVAL '3 days', NOW() + INTERVAL '3 days 6 hours', 1500, 50, 0) RETURNING id", [kF])).rows[0].id;
  await pool.query("INSERT INTO users (email, username, role, supabase_uid) VALUES ('admin@outly.si','adminf','admin','00000000-0000-4000-8000-000000000001')");
  const TF = zeton("admin@outly.si", "00000000-0000-4000-8000-000000000001");
  b = await zazeni(P4, { RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", OPOZORILA_ZDRAVJE_VELJA_MS: "300",
    GOST_NAKUP_TEST: "1", GOST_NAKUP_NA_URO: "1000", GOST_POSTA_PONOVI_MS: "500", GOST_POSTA_PREMOR_MS: "400", GOST_POSTA_TIMEOUT_MS: "1000", GOST_POSTA_REZERVA_MS: "100", GOST_NEUSPESNI_NA_URO: "1000" });
  try {
    const kupi = async (email) => {
      const r = await klic(P4, `/guest/events/${dF}/orders`, { metoda: "POST", glave: { "content-type": "application/json" }, telo: JSON.stringify({ email, quantity: 1, accept_terms: true, terms_version: "2026-10-01" }) });
      assert(r.status === 201, `gostujoc nakup ${email}`, r);
      const id = r.body.order.id;
      // pravo (ne testno) placano narocilo pred 40 min; mail vrstice so ze v poskusih
      await pool.query("UPDATE orders SET stripe_payment_intent_id = NULL, paid_at = NOW() - INTERVAL '40 minutes' WHERE id = $1", [id]);
      return id;
    };
    const cakaj = async (pogoj, ms) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await pogoj()) return true; await spi(150); } return false; };
    const poskusi = async (id) => (await pool.query("SELECT guest_mail_attempts AS n FROM orders WHERE id = $1", [id])).rows[0].n;
    const panelF = async () => (await klic(P4, "/admin/api/opozorila", { glave: { authorization: "Bearer " + TF } })).body;
    const vrsteF = (o) => (o && o.items ? o.items.map((x) => x.vrsta) : []);
    // (ii) en sam gost z napako Resenda: ORANZNO, javni 200
    const id1 = await kupi("f1@primer.si");
    assert(await cakaj(async () => (await poskusi(id1)) >= 1, 8000), "pospravljalec je poskusil poslati (attempts >= 1)");
    await spi(500);
    let rr = await zdravje(P4), pf = await panelF();
    assert(rr.status === 200 && vrsteF(pf).includes("gost_vstopnica_neposlana") && !vrsteF(pf).includes("gost_vstopnice_neposlane"), "(ii) 1 naročilo z napako Resenda: 200 + ORANZNO gost_vstopnica_neposlana", { rr, v: vrsteF(pf) });
    // (i) dve narocili z napako: po 1. poskusu 503 (rdece)
    const id2 = await kupi("f2@primer.si");
    assert(await cakaj(async () => (await poskusi(id2)) >= 1, 8000), "drugo naročilo: pospravljalec je poskusil");
    await spi(500);
    rr = await zdravje(P4); pf = await panelF();
    assert(rr.status === 503 && vrsteF(pf).includes("gost_vstopnice_neposlane"), "(i) 2 naročili z napako Resenda: 503 + RDECE gost_vstopnice_neposlane", { rr, v: vrsteF(pf) });
    R.napaka = false;
    assert(await cakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE id = ANY($1) AND guest_mail_sent_at IS NOT NULL", [[id1, id2]])).rows[0].n === 2, 15000), "ko Resend spet dela, pospravljalec poslje oba maila");
    await spi(500);
    rr = await zdravje(P4);
    assert(rr.status === 200, "po poslanih mailih spet 200", rr);
    // (iii) delno vrnjeno brez maila: delavec ga ne posilja, alarma ni
    R.napaka = true;
    const id3 = await kupi("f3@primer.si"), id4 = await kupi("f4@primer.si");
    await pool.query("UPDATE orders SET status = 'partially_refunded', refunded_cents = 100, guest_mail_attempts = 0, guest_mail_claimed_at = NULL WHERE id = ANY($1)", [[id3, id4]]);
    await spi(2500);
    const n34 = (await pool.query("SELECT COALESCE(SUM(guest_mail_attempts), 0)::int AS n FROM orders WHERE id = ANY($1)", [[id3, id4]])).rows[0].n;
    pf = await panelF(); rr = await zdravje(P4);
    assert(n34 === 0 && rr.status === 200 && !vrsteF(pf).some((v) => /^gost_/.test(v)), "(iii) delno vrnjeno brez maila: delavec ne poskusa, ni v alarmu", { n34, rr, v: vrsteF(pf) });
    // (iv) izcrpani poskusi: oranzno
    await pool.query("UPDATE orders SET status = 'paid', guest_mail_attempts = 8 WHERE id = ANY($1)", [[id3, id4]]);
    await spi(500);
    pf = await panelF(); rr = await zdravje(P4);
    assert(rr.status === 200 && vrsteF(pf).includes("gost_vstopnice_izcrpane") && !vrsteF(pf).includes("gost_vstopnice_neposlane"), "(iv) izcrpani poskusi: 200 + ORANZNO gost_vstopnice_izcrpane", { rr, v: vrsteF(pf) });
  } finally { await b.ustavi(); resendServer.close(); }

  console.log(`\n${ok} OK, ${fail} NAPAK`);
  await pool.end();
  jwksServer.close(); stripeServer.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
