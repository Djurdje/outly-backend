#!/usr/bin/env node
/**
 * Test: brisanje racuna / dogodka / kluba ob mrtvi zanki (40P01), lock_timeout (55P03) in statement_timeout (57014) vrne 503 + Retry-After, ne 500.
 * Zagon (PG16, prazna baza z vsemi migracijami; v URL-ju mora pisati `localhost`):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_brisanje_zasedenost.js
 * Trije procesi backenda (porti 4151-4153), ker meji lock_timeout / statement_timeout veljata za povezave procesa (`options` v DATABASE_URL, ne za bazo):
 *   A) deadlock_timeout 3 s, BRISANJE_ZAKLEP_MS 30 s -> 40P01: pravi cikel zaklepov (test drzi eno vrstico, DELETE zaklene drugo, test zahteva njegovo =
 *      Postgres prekine DELETE; zaklep je daljsi od deadlock_timeout, sicer bi pred ciklom odnehal lock_timeout)
 *   B) BREZ lock_timeout v `options`, BRISANJE_ZAKLEP_MS 600 -> 55P03: test drzi vrstico dlje od meje (HOLD_MS), DELETE mora odnehati v ~meji,
 *      ne cakati do sprostitve (#380 t.1: transakciji DELETE /me in DELETE /events/:id sami nastavita SET LOCAL lock_timeout)
 *   C) statement_timeout 700 ms, BRISANJE_ZAKLEP_MS 30 s -> 57014: isto, stavek caka dlje od meje (zaklep daljsi od statement_timeout)
 * Kar je 503: nic spremenjeno (ROLLBACK), Supabasov delete_my_account se NI poklical (tece pred COMMIT-om, a po vseh stavkih baze), ponovitev po sprostitvi uspe.
 * Ostale napake (npr. 23503) ostanejo 500. Admin brisanje (admin_brisanje.js) je ze imelo 503 `busy`; tu preverjamo se glavo Retry-After.
 */
const crypto = require("crypto");
const http = require("http");
const path = require("path");
const { spawn } = require("child_process");
const { Pool, Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const KOREN = path.join(__dirname, "..");
const JWKS_PORT = 4150;
const PORTI = { A: 4151, B: 4152, C: 4153 };
const dbZ = (opcije) => opcije ? DB + (DB.includes("?") ? "&" : "?") + "options=" + encodeURIComponent(opcije) : DB;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-brisanje-zasedenost";
const S = { izbrisanSupabase: 0 };
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/rest/v1/rpc/delete_my_account")) { S.izbrisanSupabase++; return res.end("{}"); }
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch { return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));   // tudi grant_type=password ob DELETE /me -> 200
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
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms));
async function cakaj(fn, ms = 8000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await fn()) return true; await pocakaj(50); } return false; }
async function api(port, method, p, token, body) {
  const r = await fetch(`http://127.0.0.1:${port}${p}`, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined || method === "GET" ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, retryAfter: r.headers.get("retry-after") };
}

async function ins(c, tab, o) {
  const k = Object.keys(o);
  const r = await c.query(`INSERT INTO ${tab} (${k.join(",")}) VALUES (${k.map((_, i) => "$" + (i + 1)).join(",")}) RETURNING *`, k.map((x) => o[x]));
  return r.rows[0];
}

const procesi = [];
const ZAKLEP_B_MS = 600;     // BRISANJE_ZAKLEP_MS procesa B
const HOLD_MS = 6000;        // zadrzevalec v B sprosti zaklep sam sele po tem casu: brez roka v kodi bi zahtevek cakal toliko (in pod tem rokom ne bi vrnil 503)
const MEJA_MS = ZAKLEP_B_MS + 2500;   // zgornja meja trajanja zahtevka z roko 600 ms (rezerva za pocasen CI; precej pod HOLD_MS)
const NIZ_NAPAKE = { "40P01": "deadlock detected", "55P03": "lock timeout", "57014": "statement timeout" };   // sporocilo Postgresa v dnevniku procesa = dokaz, da je res padla ta napaka
const stNiza = (o, kod) => o.log.split(NIZ_NAPAKE[kod]).length - 1;
async function zazeni(port, dbOpcije, okolje = {}) {
  const srv = spawn("node", ["index.js"], { cwd: KOREN, env: { ...process.env, DATABASE_URL: dbZ(dbOpcije), PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    TEST_PLACILA: "", ADMIN_BRISANJE_ZAKLEP_MS: "500", VRACILA_TICK_MS: "0", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const o = { srv, log: "" };
  srv.stdout.on("data", (d) => o.log += d); srv.stderr.on("data", (d) => o.log += d);
  procesi.push(srv);
  for (let i = 0; i < 100; i++) { try { await fetch(`http://127.0.0.1:${port}/`); break; } catch { await pocakaj(100); } }
  return o;
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  const tabele = (await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name <> 'schema_migrations'")).rows.map((x) => `"${x.table_name}"`);
  await pool.query(`TRUNCATE ${tabele.join(", ")} RESTART IDENTITY CASCADE`);
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  // Mrtva zanka: proces A (DELETE) preveri cikel po 3 s, zadrzevalec T1 sele po 60 s -> zrtev je zanesljivo DELETE, tudi ce T1 na pocasnem CI zacne cakati pozneje
  // kot privzeta 1 s (pregled #379; z deadlock_timeout=30ms je bil zrtev T1 in DELETE je uspel).
  const A = await zazeni(PORTI.A, "-c deadlock_timeout=3000", { BRISANJE_ZAKLEP_MS: "30000" });
  const B = await zazeni(PORTI.B, "", { BRISANJE_ZAKLEP_MS: String(ZAKLEP_B_MS) });   // brez lock_timeout v options: mejo postavi koda sama (SET LOCAL)
  const C = await zazeni(PORTI.C, "-c statement_timeout=700", { BRISANJE_ZAKLEP_MS: "30000" });
  const drzalci = [];
  const odjemalec = async () => { const c = new Client({ connectionString: DB }); await c.connect(); await c.query("SET deadlock_timeout = '60s'"); drzalci.push(c); return c; };

  try {
    // ---- osnova: admin, lastnik kluba, klub, dogodek za narocila
    const T = { admin: zeton("admin@outly.si", uuid(1)), lastnik: zeton("lastnik@outly.si", uuid(2)) };
    for (const k of Object.keys(T)) { const r = await api(PORTI.A, "GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    const idLastnika = (await pool.query("SELECT id FROM users WHERE email='lastnik@outly.si'")).rows[0].id;
    const klub = (await ins(pool, "clubs", { owner_user_id: idLastnika, name: "Klub zasedenost", city: "Ljubljana" })).id;
    const dogodek = async (naslov) => (await ins(pool, "events", { club_id: klub, title: naslov, start_at: new Date(Date.now() + 5 * 864e5) })).id;
    const evNarocila = await dogodek("Dogodek z narocili");

    let stKupcev = 100;
    // kupec s cakajocim (O_p) in placanim (O_k) narocilom; brez drugih odvisnosti
    async function kupec(port) {
      const n = ++stKupcev;
      const t = zeton(`kupec${n}@outly.si`, uuid(n));
      const r = await api(port, "GET", "/me", t);
      if (r.status !== 200) throw new Error("GET /me kupec: " + JSON.stringify(r));
      const uid = (await pool.query("SELECT id FROM users WHERE email=$1", [`kupec${n}@outly.si`])).rows[0].id;
      const narocilo = (status) => ins(pool, "orders", { public_ref: crypto.randomUUID().replace(/-/g, "").slice(0, 16), user_id: uid, event_id: evNarocila, club_id: klub, quantity: 1,
        unit_price_cents: 1500, total_cents: 1500, status, buyer_email: `kupec${n}@outly.si`, ...(status === "paid" ? { paid_at: new Date() } : {}) });
      const op = await narocilo("pending"), ok_ = await narocilo("paid");
      return { token: t, uid, email: `kupec${n}@outly.si`, op: op.id, ok: ok_.id };
    }
    const stanjeKupca = async (k) => {
      const u = (await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE id=$1", [k.uid])).rows[0].n;
      const o = (await pool.query("SELECT id, status, user_id, buyer_email FROM orders WHERE id = ANY($1::bigint[]) ORDER BY id", [[k.op, k.ok]])).rows;
      const sold = (await pool.query("SELECT sold_count FROM events WHERE id=$1", [evNarocila])).rows[0].sold_count;
      return JSON.stringify({ u, o, sold });
    };
    const caka = async (vzorec) => cakaj(async () => (await pool.query("SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE $1", [vzorec])).rows.length > 0);

    // Zadrzevalec: T1 drzi O_k (placano narocilo kupca). DELETE /me zaklene O_p + vrstico dogodka (sprozilec sprosti_zalogo) in nato caka na O_k.
    // `cikel`: T1 nato zahteva vrstico dogodka -> cikel O_k <-> dogodek, Postgres prekine DELETE (caka najdlje) z 40P01.
    async function brisiRacun(imeScenarija, port, proces, kod, { cikel }) {
      console.log(`\n# DELETE /me: ${imeScenarija}`);
      await pool.query("TRUNCATE omejitve");   // omejevalnik DELETE /me: 5 na uro na IP, skupen v bazi
      const k = await kupec(port);
      const pred = await stanjeKupca(k), supabasePred = S.izbrisanSupabase, logPred = stNiza(proces, kod);
      const t1 = await odjemalec();
      await t1.query("BEGIN");
      await t1.query("SELECT id FROM orders WHERE id = $1 FOR UPDATE", [k.ok]);
      const sprostiCez = !cikel && proces === B ? setTimeout(() => t1.query("ROLLBACK").catch(() => {}), HOLD_MS) : null;   // B: zaklep drzi dlje od meje
      const t0 = Date.now();
      const p = api(port, "DELETE", "/me", k.token, { password: "x" });
      let t1Cikel = null;
      if (cikel) {
        assert(await caka("%buyer_email%"), "DELETE /me caka na zaklep placanega narocila");
        t1Cikel = t1.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [evNarocila]).then(() => "ok", (e) => e.code);
      }
      const r = await p;
      const ms = Date.now() - t0;
      if (sprostiCez) clearTimeout(sprostiCez);
      assert(stNiza(proces, kod) === logPred + 1, `${kod}: v dnevniku procesa je res "${NIZ_NAPAKE[kod]}"`);
      assert(r.status === 503, `${kod}: status 503 (ne 500)`, [r.status, r.body]);
      if (sprostiCez) assert(ms >= ZAKLEP_B_MS - 100 && ms < MEJA_MS, `${kod}: odneha v ~meji (${ms} ms; meja ${ZAKLEP_B_MS} ms, zaklep se drzi ${HOLD_MS} ms), ne caka na sprostitev`, ms);
      assert(r.retryAfter === "2", `${kod}: Retry-After: 2`, r.retryAfter);
      assert(typeof r.body === "string" && /busy/i.test(r.body) && !/deadlock|timeout|canceling|code|stack/i.test(r.body), `${kod}: telo brez notranjih podrobnosti`, r.body);
      await t1.query("ROLLBACK").catch(() => {});
      if (t1Cikel) assert((await t1Cikel) === "ok", "zadrzevalec cikla ni bil prekinjen (prekinjen je DELETE /me)");
      assert((await stanjeKupca(k)) === pred, `${kod}: nic spremenjeno (racun, narocila, zaloga)`);
      assert(S.izbrisanSupabase === supabasePred, `${kod}: Supabase delete_my_account ni bil poklican`);
      const r2 = await api(port, "DELETE", "/me", k.token, { password: "x" });
      assert(r2.status === 200, "ponovitev po sprostitvi zaklepa -> 200", [r2.status, r2.body]);
      assert(S.izbrisanSupabase === supabasePred + 1, "ponovitev: Supabase racun izbrisan enkrat");
      const po = (await pool.query("SELECT id, status, user_id, buyer_email FROM orders WHERE id = ANY($1::bigint[]) ORDER BY id", [[k.op, k.ok]])).rows;
      assert((await pool.query("SELECT 1 FROM users WHERE id=$1", [k.uid])).rows.length === 0 && po.every((x) => x.user_id === null) && po.find((x) => String(x.id) === String(k.op)).status === "cancelled",
        "ponovitev: racun izbrisan, narocila anonimizirana, cakajoce preklicano", po);
    }
    await brisiRacun("mrtva zanka", PORTI.A, A, "40P01", { cikel: true });
    await brisiRacun("lock_timeout", PORTI.B, B, "55P03", { cikel: false });
    await brisiRacun("statement_timeout", PORTI.C, C, "57014", { cikel: false });

    console.log("\n# DELETE /me: druga napaka baze ostane 500");
    {
      await pool.query("TRUNCATE omejitve");
      const k = await kupec(PORTI.A);
      // FK orders_user_id -> users je SET NULL; napako 23503 izzovemo z vrstico, ki kaze na uporabnika brez ON DELETE (zacasen trigger bi bil hrupen): uporabimo omejitev na novi tabeli
      await pool.query("CREATE TABLE IF NOT EXISTS test_zasedenost_blok (u integer NOT NULL REFERENCES users(id))");
      await pool.query("INSERT INTO test_zasedenost_blok (u) VALUES ($1)", [k.uid]);
      const pred = await stanjeKupca(k), sp = S.izbrisanSupabase;
      const r = await api(PORTI.A, "DELETE", "/me", k.token, { password: "x" });
      assert(r.status === 500 && r.retryAfter === null, "23503 (tuji kljuc) -> 500 brez Retry-After", [r.status, r.body, r.retryAfter]);
      assert((await stanjeKupca(k)) === pred && S.izbrisanSupabase === sp, "23503: nic spremenjeno, Supabase ni poklican");
      await pool.query("DROP TABLE test_zasedenost_blok");
    }

    // ---- DELETE /events/:id (lastnik kluba; dogodek brez narocil se brise)
    async function brisiDogodek(imeScenarija, port, proces, kod, { cikel }) {
      console.log(`\n# DELETE /events/:id: ${imeScenarija}`);
      const ev = await dogodek("Za brisanje " + kod);
      const logPred = stNiza(proces, kod);
      const u = (await pool.query("SELECT id FROM users WHERE email='admin@outly.si'")).rows[0].id;
      await ins(pool, "event_favorites", { user_id: u, event_id: ev });
      const t1 = await odjemalec();
      await t1.query("BEGIN");
      let t1Cikel = null, p;
      if (cikel) {
        // T1 drzi priljubljeno (otroka); DELETE zaklene dogodek in kaskada caka na otroka; T1 nato zahteva dogodek -> cikel
        await t1.query("SELECT 1 FROM event_favorites WHERE event_id = $1 FOR UPDATE", [ev]);
        p = api(port, "DELETE", `/events/${ev}`, T.lastnik);
        assert(await caka("%DELETE FROM events%"), "DELETE /events caka na zaklep otroka (kaskada)");
        t1Cikel = t1.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [ev]).then(() => "ok", (e) => e.code);
      } else {
        await t1.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [ev]);
        p = api(port, "DELETE", `/events/${ev}`, T.lastnik);
      }
      const sprostiCez = !cikel && proces === B ? setTimeout(() => t1.query("ROLLBACK").catch(() => {}), HOLD_MS) : null;   // B: zaklep drzi dlje od meje
      const t0 = Date.now();
      const r = await p;
      const ms = Date.now() - t0;
      if (sprostiCez) clearTimeout(sprostiCez);
      if (sprostiCez) assert(ms >= ZAKLEP_B_MS - 100 && ms < MEJA_MS, `${kod}: odneha v ~meji (${ms} ms; meja ${ZAKLEP_B_MS} ms, zaklep se drzi ${HOLD_MS} ms), ne caka na sprostitev`, ms);
      assert(stNiza(proces, kod) === logPred + 1, `${kod}: v dnevniku procesa je res "${NIZ_NAPAKE[kod]}"`);
      assert(r.status === 503 && r.retryAfter === "2", `${kod}: 503 + Retry-After: 2`, [r.status, r.body, r.retryAfter]);
      assert(typeof r.body === "string" && /busy/i.test(r.body), `${kod}: telo pove, da je zasedeno`, r.body);
      await t1.query("ROLLBACK").catch(() => {});
      if (t1Cikel) assert((await t1Cikel) === "ok", "zadrzevalec cikla ni bil prekinjen");
      assert((await pool.query("SELECT 1 FROM events WHERE id=$1", [ev])).rows.length === 1, `${kod}: dogodek se obstaja`);
      const r2 = await api(port, "DELETE", `/events/${ev}`, T.lastnik);
      assert(r2.status === 200, "ponovitev -> 200", [r2.status, r2.body]);
    }
    await brisiDogodek("mrtva zanka", PORTI.A, A, "40P01", { cikel: true });
    await brisiDogodek("lock_timeout", PORTI.B, B, "55P03", { cikel: false });
    await brisiDogodek("statement_timeout", PORTI.C, C, "57014", { cikel: false });

    // ---- #380 t.2: poenostavljene poti brez kaskade (zastavica obstajajoNarocila, ki je ob napaki zagonske poizvedbe ostala false) ni vec
    console.log("\n# DELETE /me in DELETE /events/:id nimata poenostavljene poti (#380 t.2)");
    {
      const koda = require("fs").readFileSync(path.join(KOREN, "index.js"), "utf8");
      assert(!/obstajajoNarocila/.test(koda), "index.js nima zastavice obstajajoNarocila (tabela orders obstaja od migracije 002)");
      assert(!/to_regclass\('public\.orders'\)/.test(koda), "ni zagonske poizvedbe, katere napaka bi pustila drugo vedenje do konca procesa");
    }

    // ---- Admin brisanje dogodka in kluba: ze 503 `busy`, zdaj z glavo Retry-After (lock_timeout admina je 500 ms, ADMIN_BRISANJE_ZAKLEP_MS)
    console.log("\n# Admin DELETE /admin/api/events|clubs/:id: zaseden zapis -> 503 busy + Retry-After");
    {
      const ev = await dogodek("Admin brisanje");
      const klubZa = (await ins(pool, "clubs", { owner_user_id: idLastnika, name: "Admin brisanje klub", city: "Maribor" })).id;
      for (const [vrsta, tabela, id, pot] of [["dogodek", "events", ev, `/admin/api/events/${ev}`], ["klub", "clubs", klubZa, `/admin/api/clubs/${klubZa}`]]) {
        const t1 = await odjemalec();
        await t1.query("BEGIN");
        await t1.query(`SELECT id FROM ${tabela} WHERE id = $1 FOR UPDATE`, [id]);
        const r = await api(PORTI.A, "DELETE", pot, T.admin, { reason: "test zasedenosti" });
        await t1.query("ROLLBACK");
        assert(r.status === 503 && r.body && r.body.error === "busy", `admin ${vrsta}: 503 busy`, [r.status, r.body]);
        assert(r.retryAfter === "2", `admin ${vrsta}: Retry-After: 2`, r.retryAfter);
        assert((await pool.query(`SELECT 1 FROM ${tabela} WHERE id=$1`, [id])).rows.length === 1, `admin ${vrsta}: nic izbrisano`);
        const r2 = await api(PORTI.A, "DELETE", pot, T.admin, { reason: "test zasedenosti" });
        assert(r2.status === 200, `admin ${vrsta}: ponovitev -> 200`, [r2.status, r2.body]);
      }
    }
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
    console.log(A.log.slice(-1500), B.log.slice(-800), C.log.slice(-800));
  } finally {
    for (const c of drzalci) await c.end().catch(() => {});
    await pool.query("DROP TABLE IF EXISTS test_zasedenost_blok").catch(() => {});
    for (const p of procesi) p.kill();
    jwksServer.close();
    await pool.end().catch(() => {});
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
