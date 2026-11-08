#!/usr/bin/env node
/**
 * Alarmi iz procesa (#403, I70): srcni utrip delavcev (delavci.js), GET /healthz/opozorila, redki POZOR, serije pospravljalca Stripa.
 * Zagon (PG16, prazna baza z migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_alarmi.js
 *
 *   U  enota delavci.js (lazna ura): zaostanek po max(3 x perioda, rok), zagonski zamik, rok sprosti zastavico samo ce jo delavec poda, pozni konec starega kroga
 *      ne sprosti zastavice novega, izklopljen delavec (perioda 0) se ne registrira, pozorRedko 1x na 10 min
 *   A  cista baza: GET /healthz/opozorila -> 200 { ok: true } (SAMO ta kljuc), Cache-Control no-store; rezultat velja OPOZORILA_ZDRAVJE_VELJA_MS (predpomnjen)
 *   B  pending narocilo starejse od 45 min -> 503 + opozorilo narocila_visijo (rdece, samo stevilo) v /admin/api/opozorila; mlajse od 45 min ne; po odpravi spet 200
 *   C  obvisel delavec (racuni_pospravi, zaklep SHARE ROW EXCLUSIVE na racuni blokira INSERT) -> 503, POZOR v dnevniku; po sprostitvi spet 200
 *   D  napacen podpis webhooka -> POZOR v dnevniku, 1x v oknu (3 klici), brez glave podpisa
 *   E  pospravljalec Stripa obdela 120 kandidatov v ENEM krogu (serije po 50)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

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
    // rok in zastavica (pravi casovnik: kratek rok prek env)
    const d2 = ustvari({ log: { error: (s) => zapisi.push(s) }, env: { DELAVCI_ROK_MS: "80" } });
    const h2 = d2.registriraj("b", { periodaMs: 20 });
    let zastavica = true; const k1 = h2.zacetek(() => { zastavica = false; });
    await spi(160);
    assert(zastavica === false, "ob izteku roka se zastavica sprosti");
    assert(zapisi.filter((s) => /POZOR.*delavec b/.test(s)).length === 1, "POZOR ob izteku roka", zapisi);
    zastavica = true;                       // nov krog je prevzel zastavico
    assert(k1.konec() === false, "pozni konec starega kroga NE sme spustiti zastavice novega kroga");
    let z3 = true; const k3 = h2.zacetek(); await spi(160);
    assert(z3 === true && k3.konec() === true, "brez podane sprostitve se zastavica ne sprosti (konec() = true: zastavica je se vedno tega kroga)");
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
    const narocilo = (ref, min) => pool.query(
      `INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, created_at)
       VALUES ($1, $2, $3, 1, 1000, 1000, 'pending', 'k@x.si', NOW() - ($4::int * INTERVAL '1 minute'))`, [ref, dog, klub, min]);
    await narocilo("ALARM-MLADO", 30);
    await spi(400);
    r = await zdravje(P1);
    assert(r.status === 200 && r.body.ok === true, "pending narocilo staro 30 min ne sprozi alarma", r);
    await narocilo("ALARM-STARO", 50);
    await pool.query("UPDATE users SET supabase_uid = $2 WHERE id = $1", [a.id, "00000000-0000-4000-8000-000000000001"]);
    const T = zeton("admin@outly.si", "00000000-0000-4000-8000-000000000001");
    await klic(P1, "/me", { glave: { authorization: "Bearer " + T } });
    r = await zdravje(P1);
    assert(r.status === 200, "rezultat je predpomnjen (znotraj OPOZORILA_ZDRAVJE_VELJA_MS ostane prejsnji)", r);
    await spi(400);
    r = await zdravje(P1);
    assert(r.status === 503 && r.body.ok === false && Object.keys(r.body).join() === "ok", "pending starejse od 45 min -> 503 { ok: false }", r);
    const op = await klic(P1, "/admin/api/opozorila", { glave: { authorization: "Bearer " + T } });
    const vr = op.body && op.body.items ? op.body.items.filter((x) => x.vrsta === "narocila_visijo") : [];
    assert(op.status === 200 && vr.length === 1 && vr[0].resnost === "rdece", "opozorilo narocila_visijo (rdece)", op);
    assert(vr.length && /^1 /.test(vr[0].besedilo) && !/ALARM-|k@x\.si/.test(JSON.stringify(vr[0])), "samo stevilo, brez reference in kupca", vr);
    await pool.query("UPDATE orders SET status = 'cancelled' WHERE public_ref = 'ALARM-STARO'");
    await spi(400);
    r = await zdravje(P1);
    assert(r.status === 200 && r.body.ok === true, "po odpravi spet 200", r);
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
  b = await zazeni(P3, { STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_POSPRAVI_MS: "3000" });
  try {
    const glava = { "content-type": "application/json", "stripe-signature": "t=1700000000,v1=00ff00ffnapacen" };
    for (let i = 0; i < 3; i++) { const r = await klic(P3, "/stripe/webhook", { metoda: "POST", glave: glava, telo: "{\"id\":\"evt_1\"}" }); if (i === 0) assert(r.status === 400, "napacen podpis -> 400", r); }
    const poz = b.log().split("\n").filter((l) => /POZOR.*Stripe webhook.*podpis/i.test(l));
    assert(poz.length === 1, "napacen podpis: POZOR natanko 1x v oknu (3 klici)", poz.length);
    assert(!/napacen00|00ff00ff|evt_1/.test(b.log()), "dnevnik ne vsebuje glave podpisa ne telesa");
    // E: po prvem teku (3 s) je ob staremu LIMIT 50 obdelanih 50; nova koda ponavlja serije
    await spi(5000);
    const n = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE status = 'cancelled' AND public_ref LIKE 'POSP-%'")).rows[0].n;
    assert(n === N, `en krog obdela vse kandidate (${N}), ne samo 50`, { n, branja: S.branja });
  } finally { await b.ustavi(); }

  console.log(`\n${ok} OK, ${fail} NAPAK`);
  await pool.end();
  jwksServer.close(); stripeServer.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
