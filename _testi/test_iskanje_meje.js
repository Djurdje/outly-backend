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
 * (d) neveljaven q (prekratek, NUL) ne porabi mejnega stevca; ISKANJE_NA_URO=0 -> privzeto
 * (e) hkratna iskanja ob zaklepu: semafor ISKANJE_HKRATI, neodvisen /clubs hiter, 503 namesto 500
 * (uspesen odgovor ima staro obliko {query, clubs, events, total})
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
  return { status: r.status, besedilo, retryAfter: r.headers.get("retry-after"), iskanje: r.headers.get("x-iskanje"), ms: Date.now() - t0 };
}

// TCP posrednik pred bazo (velja SAMO za povezave iskalnega poola). odgovoriIzgubljeni: promet odjemalec -> baza tece, baza -> odjemalec se odvrze (poizvedba dosezena, odgovor ne pride).
// drzi: ko odjemalec zapre povezavo, upstream OSTANE odprt (strezniku zaprtje nikoli ne pride: polodprt TCP).
function posrednik() {
  const st = { odgovoriIzgubljeni: false, drzi: false };
  const gore = [];
  const srvP = require("net").createServer((odj) => {
    const u = new URL(DB);
    const gor = require("net").connect(Number(u.port) || 5432, u.hostname);
    gore.push(gor);
    let iskalna = null;   // povezava iskalnega poola: v zagonskem paketu ima lock_timeout (omejevalnik, glavni pool in zdravje ga nimajo; skenPool miruje)
    odj.on("data", (d) => { if (iskalna === null) iskalna = !!process.env.PROXY_VSE || d.toString("latin1").includes("lock_timeout"); gor.write(d); });
    gor.on("data", (d) => { if (!(st.odgovoriIzgubljeni && iskalna)) odj.write(d); });
    for (const x of [odj, gor]) x.on("error", () => {});
    odj.on("close", () => { if (!(st.drzi && iskalna)) gor.destroy(); });
    gor.on("close", () => odj.destroy());
  });
  return {
    st,
    zagon: () => new Promise((r) => srvP.listen(0, "127.0.0.1", () => { const u = new URL(DB); u.hostname = "localhost"; u.port = String(srvP.address().port); u.searchParams.set("application_name", "outly_test_iskanje_meje"); r(u.toString()); })),
    zapri: () => { srvP.close(); for (const g of gore) g.destroy(); },
  };
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
    assert(rez.every((x) => x.iskanje === null), "503 ob izteku poizvedbe NIMA glave X-Iskanje (prava napaka, ne zavrnitev meje)", rez.map((x) => x.iskanje));
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

    // ------------------------------------------------------------------
    console.log("\n# (d) Neveljaven q ne porabi mejnega stevca; NUL bajt -> 400; ISKANJE_NA_URO=0 -> privzeto, ne »vse 429« (ISKANJE_NA_URO=3)");
    await pool.query("TRUNCATE omejitve");
    const D = await zazeni(3173, { ISKANJE_NA_URO: "3" });
    const kratki = [];
    for (let i = 0; i < 6; i++) kratki.push((await klic(D, "/search?q=a")).status);
    assert(kratki.every((x) => x === 400), "6x prekratek q -> 400 (pred omejevalnikom)", kratki);
    const nul = [(await klic(D, "/search?q=ab%00cd")).status, (await klic(D, "/clubs?q=%00")).status, (await klic(D, "/search?q=klub&q=a%00")).status];
    assert(nul.every((x) => x === 400), "q z NUL bajtom -> 400 (ne 500)", nul);
    const veljavni = [];
    for (let i = 0; i < 4; i++) veljavni.push((await klic(D, "/search?q=klub" + i)).status);
    assert(veljavni.join() === "200,200,200,429", "400 ni pojedel meje: 3x 200, 4. 429", veljavni);
    await D.ustavi();
    await pool.query("TRUNCATE omejitve");
    const N0 = await zazeni(3174, { ISKANJE_NA_URO: "0" });
    const nic = [];
    for (let i = 0; i < 12; i++) nic.push((await klic(N0, "/search?q=klub" + i)).status);
    assert(nic.every((x) => x === 200), "ISKANJE_NA_URO=0 -> privzeta meja, ne 429", nic);
    await N0.ustavi();

    // ------------------------------------------------------------------
    console.log("\n# (e) 40 hkratnih iskanj ob zaklenjeni tabeli events: mesta + omejena vrsta, /clubs brez q ostane hiter, brez 500");
    await pool.query("TRUNCATE omejitve");
    const E = await zazeni(3175, { ISKANJE_NA_URO: "100000", ISKANJE_MEJA_MS: "1500" });
    const lock2 = await pool.connect();
    await lock2.query("BEGIN");
    await lock2.query("LOCK TABLE events IN ACCESS EXCLUSIVE MODE");
    const iskanja = Array.from({ length: 40 }, (_, i) => klic(E, "/search?q=hkrati" + i));
    await spi(300);
    // različen parameter pri vsakem klicu: nobeden ni zadetek predpomnilnika (N5)
    const neodvisen = await klic(E, "/clubs?limit=7");
    assert(neodvisen.status === 200 && neodvisen.ms < 1000, "neodvisen GET /clubs?limit=7 med iskanji: 200 v < 1 s", [neodvisen.status, neodvisen.ms]);
    const kasneje = await klic(E, "/clubs?limit=8");
    assert(kasneje.status === 200 && kasneje.ms < 1000, "drug (nepredpomnjen) GET /clubs?limit=8, ko iskanja ze potekajo/iztekajo: < 1 s", [kasneje.status, kasneje.ms]);
    const rez2 = await Promise.all(iskanja);
    const st2 = rez2.map((x) => x.status);
    assert(st2.every((x) => x === 503), "vsa hkratna iskanja -> 503 (nobenega 500, nobenega obvisenega)", st2.join());
    assert(rez2.every((x) => Number(x.retryAfter) >= 1), "503 ima Retry-After", rez2.map((x) => x.retryAfter).join());
    assert(rez2.every((x) => x.ms < 3000), "vsa v roku (meja 1,5 s + vrsta 0,5 s)", rez2.map((x) => x.ms).join());
    const takoj = rez2.filter((x) => x.ms < 400 && x.iskanje === "zasedeno").length;
    assert(takoj >= 14, "mimo 4 mest + 20 v vrsti: preostali takoj 503 z X-Iskanje: zasedeno", takoj);
    const izteklo = rez2.filter((x) => x.iskanje === null).length;
    assert(izteklo === 4, "natanko 4 iskanja z mestom: iztek poizvedbe = 503 brez X-Iskanje", izteklo);
    await lock2.query("ROLLBACK"); lock2.release();
    const po3 = await klic(E, "/search?q=klub");
    assert(po3.status === 200, "po sprostitvi zaklepa iskanje spet 200 (mesta se sprostijo)", po3.status);
    const nulCity = [(await klic(E, "/clubs?city=a%00b")).status, (await klic(E, "/clubs?q=%00")).status];
    assert(nulCity.every((x) => x === 400), "NUL v city in q (parametra, ki gresta v SQL) -> 400 (ne 500)", nulCity);
    const nulDrugo = [(await klic(E, "/clubs?neznan=%00")).status, (await klic(E, "/clubs?withCoords=%00")).status];
    assert(nulDrugo.every((x) => x === 200), "NUL v parametru, ki ga pot ne bere ali ne gre v SQL: obnasanje kot na main (200)", nulDrugo);

    // ------------------------------------------------------------------
    console.log("\n# (g) Polodprt TCP (odgovori baze izginejo, stran ne vidi zaprtja): 503 v roku, na strezniku NI seje v transakciji, ALTER TABLE uspe");
    const post = posrednik();
    const purl = await post.zagon();
    await pool.query("TRUNCATE omejitve");
    const G = await zazeni(3177, { DATABASE_URL: purl, ISKANJE_NA_URO: "100000", ISKANJE_MEJA_MS: "1000" });
    assert((await klic(G, "/search?q=klub")).status === 200, "ogrevanje prek posrednika: 200");
    post.st.odgovoriIzgubljeni = true; post.st.drzi = true;   // poizvedba DOSEZE bazo, odgovor ne pride nazaj; ob zaprtju na strani odjemalca upstream ostane odprt
    const zamrz = [];
    for (let i = 0; i < 3; i++) zamrz.push(await klic(G, "/search?q=zamrzni" + i));
    assert(zamrz.every((x) => x.status === 503), "iskanja ob polodprti povezavi -> 503", zamrz.map((x) => x.status));
    assert(zamrz.every((x) => x.ms < 3500), "503 v roku (meja 1 s + odjemalski rok 1 s), ne visi", zamrz.map((x) => x.ms));
    assert(zamrz.every((x) => x.iskanje === null), "iztek odjemalskega roka: 503 brez X-Iskanje", zamrz.map((x) => x.iskanje));
    if (process.env.IZPIS_LOGA) console.log(G.log.slice(-1800));
    await spi(300);
    const sej = (await pool.query("SELECT state, count(*)::int AS n FROM pg_stat_activity WHERE application_name = 'outly_test_iskanje_meje' AND pid <> pg_backend_pid() GROUP BY state")).rows;
    const vTx = sej.filter((x) => /in transaction/.test(x.state || "")).reduce((n, x) => n + x.n, 0);
    assert(vTx === 0, "na strezniku NI seje 'idle in transaction' (brez odprte transakcije z zaklepom na clubs)", sej);
    const al = new Pool({ connectionString: DB, max: 1, options: "-c lock_timeout=2000" });
    let alterOk = false, alterNapaka = null;
    try { await al.query("ALTER TABLE clubs ADD COLUMN iskanje_test_x int"); alterOk = true; await al.query("ALTER TABLE clubs DROP COLUMN iskanje_test_x"); } catch (e) { alterNapaka = e.message; }
    await al.end();
    assert(alterOk, "ALTER TABLE clubs ADD COLUMN z lock_timeout 2 s uspe (migracija ob deployu ne obvisi)", alterNapaka);
    post.st.odgovoriIzgubljeni = false; post.st.drzi = false;
    const glavni = await klic(G, "/clubs?limit=5");
    assert(glavni.status === 200, "glavni pool je med tem delal normalno (/clubs brez q)", glavni.status);
    await G.ustavi(); post.zapri();

    // ------------------------------------------------------------------
    console.log("\n# (f) Obremenitev z razlicnimi q (odprta zanka): delez 503 pri ~15 / ~50 / ~100 iskanj/s");
    async function obremeni(p, hitrost, sekunde) {
      const rez = [];
      const korak = 1000 / hitrost, n = Math.round(hitrost * sekunde), t0 = Date.now();
      const vse = [];
      for (let i = 0; i < n; i++) {
        const kdaj = t0 + i * korak;
        await spi(Math.max(0, kdaj - Date.now()));
        vse.push(klic(p, "/search?q=ob" + hitrost + "x" + i).then((x) => rez.push(x)));
      }
      await Promise.all(vse);
      const nap = rez.filter((x) => x.status === 503).length;
      return { n: rez.length, delez503: nap / rez.length, drugo: rez.filter((x) => x.status !== 200 && x.status !== 503).length };
    }
    const F = await zazeni(3176, { ISKANJE_NA_URO: "1000000" });
    for (const h of [15, 50, 100]) {
      const m = await obremeni(F, h, 4);
      console.log(`    izmerjeno: ${h}/s -> ${m.n} zahtevkov, 503: ${(m.delez503 * 100).toFixed(1)} %, drugi statusi: ${m.drugo}`);
      if (h <= 50) assert(m.delez503 < 0.01 && m.drugo === 0, `${h} iskanj/s z razlicnimi q: < 1 % 503, brez 500`, m);
      else assert(m.drugo === 0, `${h} iskanj/s: brez 500`, m);
    }
    await F.ustavi();
    await E.ustavi();
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
  } finally {
    for (const p of procesi) await p.ustavi().catch(() => {});
    await pool.end().catch(() => {});
  }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
