#!/usr/bin/env node
/**
 * Meje javnega iskanja (issue #405, invarianta I69). Zagon (lokalno, PG16, vse migracije):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_iskanje_meje.js
 *
 * GET /search in GET /clubs?q= (ILIKE '%q%' po opisu, glavni pool, nakljucen q obide predpomnilnik):
 * (a) omejevalnik na IP: po meji 429 (isto besedilo + Retry-After kot ostali omejevalniki), deljen kljuc obeh poti,
 *     GET /clubs brez q se ne steje
 * (b) predolg q se obreze na 64 znakov (iOS in splet dolzine ne omejujeta: napaka pri normalni rabi bi bila hujsa od obreza)
 * (c) casovna meja: poizvedba, ki obvisi (ACCESS EXCLUSIVE na clubs), da 503 + Retry-After, proces zivi, povezave se vrnejo v pool
 * (d) uspesen odgovor ima staro obliko {query, clubs, events, total}
 */
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const dbZImenom = DB + (DB.includes("?") ? "&" : "?") + "application_name=outly_test_iskanje_meje";

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

const procesi = [];
async function zazeni(port, env) {
  const srv = spawn("node", ["index.js"], {
    env: { ...process.env, PORT: String(port), DATABASE_URL: dbZImenom, RESEND_API_KEY: "", QR_SECRET: "test-iskanje-meje-skrivnost-0123456789", ...(env || {}) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const p = { port, base: `http://127.0.0.1:${port}`, log: "", srv, umrl: null };
  srv.stdout.on("data", (d) => p.log += d); srv.stderr.on("data", (d) => p.log += d);
  srv.on("exit", (code, sig) => { p.umrl = { code, sig }; });
  procesi.push(p);
  for (let i = 0; i < 80 && p.umrl === null; i++) { try { await fetch(p.base + "/"); break; } catch { await spi(100); } }
  if (p.umrl !== null) throw new Error(`proces na portu ${port} je umrl ob zagonu: ${p.log.slice(-300)}`);
  p.ustavi = async () => { if (p.umrl === null) { srv.kill(); for (let i = 0; i < 50 && p.umrl === null; i++) await spi(50); } };
  return p;
}
async function klic(p, pot) {
  const t0 = Date.now();
  const r = await fetch(p.base + pot, { signal: AbortSignal.timeout(6000) }).catch((e) => ({ status: 0, text: async () => String(e), headers: new Headers() }));   // obvisel klic = status 0
  const besedilo = await r.text();
  return { status: r.status, besedilo, retryAfter: r.headers.get("retry-after"), ms: Date.now() - t0 };
}

(async () => {
  const pool = new Pool({ connectionString: DB, max: 3 });
  pool.on("error", () => {});
  await pool.query("TRUNCATE omejitve, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  const u = (await pool.query("INSERT INTO users (email, username) VALUES ('iskanje@test.si', 'iskanje') RETURNING id")).rows[0].id;
  await pool.query("INSERT INTO clubs (owner_user_id, name, city, description) VALUES ($1, 'Klub Iskanje', 'Ljubljana', 'testni opis')", [u]);

  try {
    // ------------------------------------------------------------------
    console.log("\n# (a) Omejevalnik na IP (ISKANJE_NA_URO=5)");
    const A = await zazeni(3171, { ISKANJE_NA_URO: "5" });
    const staro = await klic(A, "/search?q=klub");
    const o = JSON.parse(staro.besedilo);
    assert(staro.status === 200 && o.query === "klub" && Array.isArray(o.clubs) && Array.isArray(o.events) && o.total === o.clubs.length + o.events.length && o.clubs.length === 1,
      "uspesen /search ima staro obliko {query, clubs, events, total}", staro.besedilo.slice(0, 200));
    assert(Object.keys(o).join() === "query,clubs,events,total", "ključi odgovora ostanejo v starem vrstnem redu", Object.keys(o));
    const prosti = [];
    for (let i = 0; i < 3; i++) prosti.push((await klic(A, "/clubs")).status);
    assert(prosti.every((s) => s === 200), "GET /clubs brez q se ne steje v mejo", prosti);
    const c1 = await klic(A, "/clubs?q=klub");
    assert(c1.status === 200 && JSON.parse(c1.besedilo).length === 1, "GET /clubs?q= deluje (2. poskus iz meje 5)", c1.status);
    const znotraj = [];
    for (let i = 0; i < 3; i++) znotraj.push((await klic(A, "/search?q=ab" + i)).status);
    assert(znotraj.every((s) => s === 200), "3. do 5. poskus (deljen kljuc obeh poti) -> 200", znotraj);
    const r6 = await klic(A, "/search?q=klub");
    assert(r6.status === 429, "6. poskus na /search -> 429", r6.status);
    assert(r6.besedilo === "Too many requests. Please try again later.", "429: isto besedilo kot ostali omejevalniki", r6.besedilo);
    const ra = Number(r6.retryAfter);
    assert(Number.isInteger(ra) && ra >= 3590 && ra <= 3600, "429: Retry-After je ostanek okna (~3600 s)", r6.retryAfter);
    const r7 = await klic(A, "/clubs?q=klub");
    assert(r7.status === 429, "GET /clubs?q= deli mejo s /search -> 429", r7.status);
    const r8 = await klic(A, "/clubs");
    assert(r8.status === 200, "GET /clubs brez q kljub preseženi meji -> 200", r8.status);
    await A.ustavi();

    // ------------------------------------------------------------------
    console.log("\n# (b) Dolg q: obrez na 64 znakov, brez napake (visoka meja)");
    await pool.query("TRUNCATE omejitve");
    const B = await zazeni(3172, { ISKANJE_NA_URO: "1000", ISKANJE_MEJA_MS: "400" });
    const dolg = "a".repeat(200);
    const d = await klic(B, "/search?q=" + dolg);
    const dj = d.status === 200 ? JSON.parse(d.besedilo) : null;
    assert(d.status === 200 && dj.query === "a".repeat(64) && dj.total === 0, "/search z 200 znaki -> 200, query obrezan na 64", [d.status, dj && dj.query.length]);
    const tocno = "b".repeat(64);
    const t = await klic(B, "/search?q=" + tocno);
    assert(t.status === 200 && JSON.parse(t.besedilo).query === tocno, "q z natanko 64 znaki ostane nespremenjen", t.status);
    const cd = await klic(B, "/clubs?q=" + dolg);
    assert(cd.status === 200 && cd.besedilo === "[]", "/clubs?q= z 200 znaki -> 200 (obrez, ne napaka)", [cd.status, cd.besedilo.slice(0, 50)]);
    const kratek = await klic(B, "/search?q=a");
    assert(kratek.status === 400 && kratek.besedilo === "Query must be at least 2 characters.", "q z 1 znakom -> 400 kot prej", [kratek.status, kratek.besedilo]);
    const dvojna = await klic(B, "/search?q=klub&q=xx");
    assert(dvojna.status === 200, "q podan dvakrat (niz) ne podre poti", dvojna.status);

    // ------------------------------------------------------------------
    console.log("\n# (c) Casovna meja 400 ms: obvisela poizvedba -> 503 + Retry-After, povezave nazaj v pool");
    const lock = await pool.connect();
    await lock.query("BEGIN");
    await lock.query("LOCK TABLE clubs IN ACCESS EXCLUSIVE MODE");
    const rez = [];
    for (const pot of ["/search?q=zaklep0", "/clubs?q=zaklep1"]) rez.push(await klic(B, pot));
    // vec zaporednih iztekov kot je povezav v poolu (PG_POOL_MAX privzeto 10): povezava se mora vrniti, sicer pool zmanjka
    for (let i = 2; i < 14; i++) rez.push(await klic(B, "/search?q=zaklep" + i));
    assert(rez.every((x) => x.status === 503), "vsi iztekli klici -> 503", rez.map((x) => x.status));
    assert(rez.every((x) => Number(x.retryAfter) >= 1), "503 ima Retry-After", rez.map((x) => x.retryAfter));
    assert(rez.every((x) => x.ms < 3000), "klic traja ~mejo, ne deset sekund", rez.map((x) => x.ms));
    assert(rez.every((x) => !/error|stack|57014|statement/i.test(x.besedilo)), "telo 503 ne razkriva napake baze", rez[0].besedilo);
    const zivi = await klic(B, "/healthz");
    assert(B.umrl === null && zivi.status !== 0, "proces po iztekih zivi", zivi.status);
    await lock.query("ROLLBACK"); lock.release();
    const po = await klic(B, "/search?q=klub");
    assert(po.status === 200 && JSON.parse(po.besedilo).clubs.length === 1, "po sprostitvi zaklepa /search spet 200", po.status);
    const po2 = await klic(B, "/clubs?q=klub");
    assert(po2.status === 200, "po sprostitvi zaklepa /clubs?q= spet 200", po2.status);
    const cakajoci = (await pool.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name = 'outly_test_iskanje_meje' AND state = 'idle in transaction'")).rows[0].n;
    assert(cakajoci === 0, "nobena povezava ne ostane v odprti transakciji", cakajoci);
    await B.ustavi();
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
  } finally {
    for (const p of procesi) await p.ustavi().catch(() => {});
    await pool.end().catch(() => {});
  }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
