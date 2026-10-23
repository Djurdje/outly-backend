#!/usr/bin/env node
/**
 * Samodejna objava osnutka ob casu (#327, »PR B« nacrta admin panela 23. 10. 2026; migracija 062, invarianta I59). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_samodejna_objava.js
 * Vzorec kot test_push.js (lokalni JWKS, lazni APNs prek http2, backend kot otrok proces) in test_admin_podvoji.js (klubi, osnutki). Brez fiksnega cakanja: vse je cakanje
 * na pogoj (stanje v bazi, vrstica v dnevniku procesa, zahtevek na APNs). Delavec tece na kratkem intervalu (SAMODEJNA_OBJAVA_MS=200), v 1. delu pa se kliče izpostavljen krog().
 *
 *  M (modul, dve instanci delavca na isti bazi, brez omrezja)
 *   M1  dve instanci hkrati: vsak osnutek objavi natanko ena (vsota objav = stevilo osnutkov, ena vrstica dnevnika in en klic naObjavljen na osnutek)
 *   M2  zaklenjena vrstica dogodka (nakup/PATCH v teku, FOR NO KEY UPDATE): krog se NE zaustavi (SKIP LOCKED), dogodek ostane osnutek, po sprostitvi ga objavi naslednji krog;
 *       KEY SHARE (kot tuji kljuc nakupa) objave ne ustavi; ACCESS EXCLUSIVE na events (migracija): krog odneha po lock_timeout in ne obvisi; po sprostitvi spet dela
 *   M3  napaka obvestila (naObjavljen vrze): dogodek ostane objavljen, krog ne vrze; rdeca ovira in neuspel pregled: osnutek ostane (fail-closed); dogodek, ki se je zacel: ostane;
 *       izbrisan med seznamom in objavo: brez napake
 *  P (backend, dva procesa z delavcem + lazni APNs)
 *   P1  PATCH publishAt: veljavno (camel in snake_case), vloge (lastnik 200, tuj 403), null = preklic, formati, pred zacetkom, samo osnutek (objavljen/odpovedan 400),
 *       stanje + publishAt v istem zahtevku, sprememba stanja pobrise cas (rocna objava, »Med osnutke«, admin pot), brez publishAt v telesu cas ostane
 *   P2  odgovori: GET /admin/api/events (seznam in :id) imata publish_at; javni odgovori in /business/events ga NE kazejo
 *   P3  dva procesa: ena objava (en zapis v dnevniku event.publish_auto, brez admina), ena vrstica v zvoncu, en push; odpovedan/prihodnji/preklican dogodek se ne objavi
 *   P4  push pade (APNs 500) in obvestilo pade (sprozilec v bazi): dogodek ostane objavljen (I29)
 *   P5  isti pogoji kot rocna objava: rdeca ovira (klub z nepopolnimi podatki) in dogodek, ki se je zacel: osnutek ostane + rdece opozorilo objava_zamujena v /admin/api/opozorila
 *       (v pregledu ENEGA dogodka ga ni); ko ovira izgine, se objavi
 *   P6  javni predpomnilnik: objavljeni dogodek je takoj viden (razveljavitev), ne cez TTL
 */
const crypto = require("crypto");
const http = require("http");
const http2 = require("http2");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, execFileSync } = require("child_process");
const { Pool, Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT1 = 6301, PORT2 = 6302, PORT3 = 6303, JWKS_PORT = 6304, APNS_PORT = 6305;
const BASE1 = `http://127.0.0.1:${PORT1}`, BASE3 = `http://127.0.0.1:${PORT3}`;

// --- identiteta (lokalni JWKS kot v ostalih testih) ---
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-objava";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
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
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const cakaj = (ms) => new Promise((r) => setTimeout(r, ms));
async function pocakaj(pogoj, ms = 15000) {   // poll na pogoj (ne fiksno spanje)
  const konec = Date.now() + ms;
  while (Date.now() < konec) { if (await pogoj()) return true; await cakaj(25); }
  return false;
}
let ipSt = 0;
async function apiNa(baza, method, p, token, body) {
  const r = await fetch(baza + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.79.${(++ipSt >> 8) & 255}.${(ipSt & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, besedilo: t };
}
const api = (...a) => apiNa(BASE1, ...a);

// --- lazni APNs (kot test_push.js) ---
const mapa = fs.mkdtempSync(path.join(os.tmpdir(), "outly-objava-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", path.join(mapa, "k.pem"), "-out", path.join(mapa, "c.pem"),
  "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { stdio: "ignore" });
const APNS_P8_B64 = Buffer.from(crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" })).toString("base64");
const zahteve = [];     // sprejeti zahtevki APNs { zeton, json }
let rezimApns = "ok";   // "ok" | "500"
const apnsStreznik = http2.createSecureServer({ key: fs.readFileSync(path.join(mapa, "k.pem")), cert: fs.readFileSync(path.join(mapa, "c.pem")) });
apnsStreznik.on("session", (s) => s.on("error", () => {}));
apnsStreznik.on("stream", (stream, glave) => {
  stream.on("error", () => {});
  let telo = ""; stream.setEncoding("utf8"); stream.on("data", (d) => telo += d);
  stream.on("end", () => {
    let json = null; try { json = JSON.parse(telo); } catch { /* ostane null */ }
    zahteve.push({ zeton: String(glave[":path"]).split("/").pop(), json });
    try {
      if (rezimApns === "500") { stream.respond({ ":status": 500, "content-type": "application/json" }); stream.end(JSON.stringify({ reason: "InternalServerError" })); }
      else { stream.respond({ ":status": 200 }); stream.end(""); }
    } catch { /* seja zavrzena */ }
  });
});
const pushiZa = (eventId) => zahteve.filter((z) => z.json && z.json.outly && z.json.outly.type === "club_event" && z.json.outly.id === eventId);

const procesi = [];
function zazeniBackend(port, dodatno = {}) {
  const env = { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_live_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_lokalno", STRIPE_API_BASE: "http://127.0.0.1:1", TEST_PLACILA: "", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0",
    SAMODEJNA_OBJAVA_MS: "200", APNS_KEY_ID: "TESTKEYID1", APNS_TEAM_ID: "TESTTEAM12", APNS_KEY_P8: APNS_P8_B64, APNS_HOST: `https://localhost:${APNS_PORT}`,
    NODE_EXTRA_CA_CERTS: path.join(mapa, "c.pem"), APNS_TIMEOUT_MS: "2500", ...dodatno };
  const o = { proc: spawn("node", ["index.js"], { env, stdio: ["ignore", "pipe", "pipe"] }), log: "" };
  o.proc.stdout.on("data", (d) => o.log += d); o.proc.stderr.on("data", (d) => o.log += d);
  procesi.push(o);
  return o;
}
async function cakajNaStrezbo(baza) { for (let i = 0; i < 100; i++) { try { await fetch(baza + "/"); return true; } catch { await cakaj(100); } } return false; }
const vLogu = (iskano) => procesi.some((p) => p.log.includes(iskano));
const stVLogu = (re) => procesi.reduce((n, p) => n + (p.log.match(re) || []).length, 0);

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, admin_dejanja, device_tokens, club_event_notifications, club_follows, club_members, event_favorites, tickets, orders, club_tables, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  await new Promise((r) => apnsStreznik.listen(APNS_PORT, r));
  const lock = new Client({ connectionString: DB });
  const lock2 = new Client({ connectionString: DB });
  await lock.connect(); await lock2.connect();
  let p1 = null, p2 = null, p3 = null;
  const sprozilec = async (sql) => pool.query(sql);

  try {
    // =================================================================================================================
    console.log("\n# M: modul samodejna_objava.js, dve instanci na isti bazi");
    const { ustvari } = require("../samodejna_objava");
    // admin_dejanja brez index.js: ista oblika vrstice (zapisiAdminDejanje je tam); samo stolpci, ki jih modul poda
    const zapisi = async (c, req, dejanje, tip, id, prej, potem) => c.query(
      "INSERT INTO admin_dejanja (admin_user_id, dejanje, cilj_tip, cilj_id, prej, potem) VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb)",
      [req.user.userId === undefined ? null : req.user.userId, dejanje, tip, String(id), JSON.stringify(prej), JSON.stringify(potem)]);
    const klicani = [];
    const modul = (ovira = async () => ({ items: [] }), naObj = async (id) => { klicani.push(id); }) =>
      ustvari({ pool: new Pool({ connectionString: DB, max: 3 }), zapisiAdminDejanje: zapisi, opozorilaDogodka: ovira, naObjavljen: naObj, log: { log() {}, error() {} } });
    const uid = (await pool.query("INSERT INTO users (email, username, role) VALUES ('m@primer.si', 'mlastnik', 'business') RETURNING id")).rows[0].id;
    const klubM = (await pool.query("INSERT INTO clubs (owner_user_id, name) VALUES ($1, 'Modulni klub') RETURNING id", [uid])).rows[0].id;
    const osnutek = async (naslov, polja = {}) => {
      const e = { status: "draft", start: "10 days", publish: "-1 minute", ...polja };
      return (await pool.query(
        `INSERT INTO events (club_id, title, status, start_at, end_at, ticket_price_cents, capacity, publish_at)
         VALUES ($1, $2, $3, NOW() + $4::interval, NOW() + $4::interval + INTERVAL '6 hours', 0, 100, CASE WHEN $5::text IS NULL THEN NULL ELSE NOW() + $5::interval END) RETURNING id`,
        [klubM, naslov, e.status, e.start, e.publish])).rows[0].id;
    };
    const stanje = async (id) => (await pool.query("SELECT status, publish_at FROM events WHERE id = $1", [id])).rows[0];
    const dnevnikAuto = async (id) => (await pool.query("SELECT admin_user_id, prej, potem FROM admin_dejanja WHERE dejanje = 'event.publish_auto' AND cilj_tip = 'event' AND cilj_id = $1", [String(id)])).rows;

    // --- M1: dve instanci hkrati ---
    for (let ponovitev = 1; ponovitev <= 3; ponovitev++) {
      klicani.length = 0;
      const ids = [];
      for (let i = 0; i < 12; i++) ids.push(await osnutek(`Tek ${ponovitev}/${i}`));
      const a = modul(), b = modul();
      const [ra, rb] = await Promise.all([a.krog(), b.krog()]);
      let konec = ids.length - ra.objavljenih - rb.objavljenih;   // morebitno preskocene (zaklep druge instance) dokonca naslednji krog
      for (let i = 0; i < 5 && konec > 0; i++) { const r = await a.krog(); konec -= r.objavljenih; }
      const st = await Promise.all(ids.map(stanje));
      assert(st.every((x) => x.status === "published" && x.publish_at === null), `M1.${ponovitev}: vseh 12 osnutkov objavljenih, publish_at pobrisan`, st.map((x) => x.status));
      assert(klicani.length === ids.length && new Set(klicani).size === ids.length, `M1.${ponovitev}: naObjavljen natanko enkrat na dogodek (${klicani.length} klicev, ${new Set(klicani).size} razlicnih)`);
      const dn = await Promise.all(ids.map(dnevnikAuto));
      assert(dn.every((v) => v.length === 1 && v[0].admin_user_id === null && v[0].prej.status === "draft" && typeof v[0].prej.publish_at === "string" && v[0].potem.status === "published" && v[0].potem.publish_at === null),
        `M1.${ponovitev}: natanko ena vrstica event.publish_auto na dogodek, brez admina, prej/potem`, dn.map((v) => v.length));
      assert(ra.objavljenih + rb.objavljenih <= ids.length, `M1.${ponovitev}: skupaj ne vec objav kot dogodkov (${ra.objavljenih}+${rb.objavljenih})`);
    }

    // --- M2: zaklepi ---
    {
      klicani.length = 0;
      const e = await osnutek("Zaklenjen");
      const m = modul();
      await lock.query("BEGIN");
      await lock.query("SELECT id FROM events WHERE id = $1 FOR NO KEY UPDATE", [e]);   // kot PATCH, odpoved ali nakup z zaklepom vrstice
      const t0 = Date.now();
      const r1 = await m.krog();
      const dt = Date.now() - t0;
      assert(r1.objavljenih === 0 && r1.preskocenih === 1 && dt < 900, `M2: zaklenjena vrstica: krog ne caka (SKIP LOCKED): ${dt} ms, preskoceno ${r1.preskocenih}`, [r1, dt]);
      assert((await stanje(e)).status === "draft", "M2: dogodek ostane osnutek, dokler je zaklenjen");
      await lock.query("ROLLBACK");
      const r2 = await m.krog();
      assert(r2.objavljenih === 1 && (await stanje(e)).status === "published" && klicani.join() === String(e), "M2: po sprostitvi ga objavi naslednji krog (en klic naObjavljen)", [r2, klicani]);

      // KEY SHARE = tuji kljuc nakupa (orders.event_id): objave NE ustavi
      const e2 = await osnutek("Nakup drzi KEY SHARE");
      await lock.query("BEGIN");
      await lock.query("SELECT id FROM events WHERE id = $1 FOR KEY SHARE", [e2]);
      const t1 = Date.now();
      const r3 = await m.krog();
      assert(r3.objavljenih === 1 && Date.now() - t1 < 900 && (await stanje(e2)).status === "published", "M2: KEY SHARE (vstavljanje narocila) objave ne ustavi in je ne zaklene", r3);
      await lock.query("ROLLBACK");

      // migracija / ALTER: ACCESS EXCLUSIVE na events. Krog mora odnehati po lock_timeout (1 s), ne obviseti; nobeno branje ne sme cakati zaradi delavca.
      const e3 = await osnutek("Migracija drzi events");
      await lock.query("BEGIN");
      await lock.query("LOCK TABLE events IN ACCESS EXCLUSIVE MODE");
      const t2 = Date.now();
      const r4 = await m.krog();
      const dt2 = Date.now() - t2;
      assert(r4.napaka === true && r4.objavljenih === 0 && dt2 < 4000, `M2: ACCESS EXCLUSIVE na events: krog odneha po lock_timeout (${dt2} ms), brez izjeme`, [r4, dt2]);
      const caka = (await pool.query("SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query ILIKE '%FROM events%' AND pid <> pg_backend_pid()")).rows[0].n;
      assert(caka === 0, "M2: po koncu kroga nobena seja delavca ne caka na zaklep (idle in transaction ni)", caka);
      await lock.query("ROLLBACK");
      const r5 = await m.krog();
      assert(r5.objavljenih === 1 && (await stanje(e3)).status === "published", "M2: po sprostitvi zaklepa delavec spet dela");
      const mirujoce = (await pool.query("SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE state = 'idle in transaction' AND pid <> pg_backend_pid()")).rows[0].n;
      assert(mirujoce === 0, "M2: delavec ne pusti odprte transakcije", mirujoce);
    }

    // --- M3: napake, ovire ---
    {
      klicani.length = 0;
      const e = await osnutek("Obvestilo pade");
      const m = modul(undefined, async () => { throw new Error("obvestilo pade"); });
      let izjema = null, r = null;
      try { r = await m.krog(); } catch (x) { izjema = x; }
      assert(!izjema && r.objavljenih === 1 && (await stanje(e)).status === "published", "M3: naObjavljen vrze: krog ne vrze, dogodek ostane objavljen (I29)", [izjema && izjema.message, r]);

      const rdec = await osnutek("Rdeca ovira");
      const mr = modul(async (id) => ({ items: id === rdec ? [{ vrsta: "prodajalec_nepopoln", resnost: "rdece" }, { vrsta: "brez_plakata", resnost: "oranzno" }] : [] }));
      const rr = await mr.krog();
      assert(rr.objavljenih === 0 && rr.preskocenih === 1 && (await stanje(rdec)).status === "draft" && (await stanje(rdec)).publish_at !== null, "M3: rdeca ovira: osnutek ostane in cas objave ostane (za naslednji krog)", rr);
      const oranzno = await osnutek("Samo oranzno");
      const mo = modul(async () => ({ items: [{ vrsta: "brez_plakata", resnost: "oranzno" }, { vrsta: "brez_konca", resnost: "rumeno" }] }));
      await pool.query("UPDATE events SET publish_at = NULL WHERE id = $1", [rdec]);   // rdeci dogodek iz igre
      const ro = await mo.krog();
      assert(ro.objavljenih === 1 && (await stanje(oranzno)).status === "published", "M3: oranzno in rumeno opozorilo objave ne ustavita (kot gumb »Objavi« v panelu)", ro);

      const padel = await osnutek("Pregled pade");
      for (const [ime, f] of [["izjema", async () => { throw new Error("pregled pade"); }], ["brez odgovora", async () => undefined], ["neveljaven odgovor", async () => ({ items: "x" })]]) {
        const mp = modul(f);
        const rp = await mp.krog();
        assert(rp.objavljenih === 0 && (await stanje(padel)).status === "draft", `M3: pregled pred objavo ni uspel (${ime}): osnutek ostane (fail-closed)`, rp);
      }
      await pool.query("UPDATE events SET publish_at = NULL WHERE id = $1", [padel]);

      const zacet = await osnutek("Ze zacet", { start: "-30 minutes" });
      const mz = modul();
      const rz = await mz.krog();
      assert(rz.objavljenih === 0 && (await stanje(zacet)).status === "draft", "M3: dogodek, ki se je ze zacel, se ne objavi (in ne pade)", rz);
      await pool.query("UPDATE events SET publish_at = NULL WHERE id = $1", [zacet]);

      const odpovedan = await osnutek("Odpovedan", { status: "cancelled" });
      const prihodnji = await osnutek("V prihodnosti", { publish: "1 hour" });
      const brez = await osnutek("Brez casa", { publish: null });
      const rn = await modul().krog();
      assert(rn.objavljenih === 0 && (await stanje(odpovedan)).status === "cancelled" && (await stanje(prihodnji)).status === "draft" && (await stanje(brez)).status === "draft",
        "M3: odpovedan, v prihodnosti in brez casa: nic se ne objavi (tudi kandidati niso)", rn);
      const izb = await osnutek("Izbrisan");
      const mi = modul();
      await pool.query("DELETE FROM events WHERE id = $1", [izb]);
      assert((await mi.objavi(izb)) === null, "M3: izbrisan med seznamom in objavo: objavi() vrne null brez napake");
      // delavec ne sme uporabljati skenPool: modul sprejme samo `pool`
      assert(!/skenPool/.test(fs.readFileSync(path.join(__dirname, "..", "samodejna_objava.js"), "utf8").replace(/\/\/.*$/gm, "")), "M3: samodejna_objava.js ne omenja skenPool (I16)");
    }
    // --- M4: stradanje (pregled #347 S2): zataknjeni osnutki ne smejo zasesti kroga ---
    {
      klicani.length = 0;
      const zataknjeni = [];
      for (let i = 0; i < 25; i++) zataknjeni.push(await osnutek(`Zacet ${i}`, { start: "-1 hour", publish: "-3 hours" }));   // ze zaceti, najstarejsi publish_at
      const rdeci = [];
      for (let i = 0; i < 25; i++) rdeci.push(await osnutek(`Rdec ${i}`, { publish: "-2 hours" }));
      const veljaven = await osnutek("Nov veljaven", { publish: "-1 minute" });
      const rdeciSet = new Set(rdeci);
      const m = modul(async (id) => ({ items: rdeciSet.has(id) ? [{ vrsta: "prodajalec_nepopoln", resnost: "rdece" }] : [] }));
      const kand = await m.kandidati();
      assert(!kand.some((id) => zataknjeni.includes(id)), "M4: ze zaceti osnutki niso kandidati (start_at > NOW() v izboru)", kand.length);
      const r1 = await m.krog();
      assert(r1.objavljenih === 1 && (await stanje(veljaven)).status === "published", "M4: 25 ze zacetih + 25 z rdeco oviro + 1 veljaven: veljaven je objavljen v ENEM krogu", r1);
      // rotacija: po vec krogih so obravnavani vsi rdeci (najprej tisti, ki jih se nismo poskusili), nov veljaven spet takoj
      const rdeciNov = await osnutek("Se en rdec", { publish: "-30 minutes" }); rdeciSet.add(rdeciNov);
      const veljaven2 = await osnutek("Nov veljaven 2", { publish: "-1 minute" });
      const r2 = await m.krog();
      assert(r2.objavljenih === 1 && (await stanje(veljaven2)).status === "published", "M4: tudi po prvem krogu nov veljaven pride na vrsto takoj (zataknjeni se vrtijo)", r2);
      const dnevnikOpomb = []; 
      await pool.query("DELETE FROM events WHERE id = ANY($1::int[]) OR id = ANY($2::int[]) OR id = $3", [zataknjeni, rdeci, rdeciNov]);
    }
    // --- M5: DELETE /events/:id z narocili je odpoved: publish_at se pobrise (preverjeno v P-delu) ---
    await pool.query("TRUNCATE admin_dejanja, events RESTART IDENTITY CASCADE");

    // =================================================================================================================
    console.log("\n# P: backend (dva procesa z delavcem) + lazni APNs");
    p1 = zazeniBackend(PORT1); p2 = zazeniBackend(PORT2);
    assert(await cakajNaStrezbo(BASE1) && await cakajNaStrezbo(`http://127.0.0.1:${PORT2}`), "oba backenda sta se zagnala");

    const imena = ["admin", "lastnik", "tuj", "vratar", "sledilec", "kupec"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    const U = {};
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','tuj@outly.si')");
    await pool.query("UPDATE users SET date_of_birth='1990-01-01'");
    const klubi = {};
    const klub = async (ime, lastnik, polja = {}) => {
      const k = { stripe: true, popoln: true, ...polja };
      return (await pool.query(
        `INSERT INTO clubs (owner_user_id, name, stripe_account_id, stripe_charges_enabled, stripe_payouts_enabled, stripe_account_livemode, legal_name, legal_address, registration_number, tax_number, vat_payer, contact_email)
         VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
        [lastnik, ime, k.stripe ? "acct_o" + ime.length + ime.charCodeAt(0) : null, k.stripe, k.stripe ? true : null,
         k.popoln ? "Klub d.o.o." : "", k.popoln ? "Ulica 1, 1000 Ljubljana" : "", k.popoln ? "1234567" : "", k.popoln ? "SI12345678" : "", k.popoln ? true : null, k.popoln ? "info@klub.si" : ""])).rows[0].id;
    };
    klubi.moj = await klub("Pure Club", U.lastnik);
    klubi.tuj = await klub("Tuj Klub", U.tuj);
    const uNepopoln = (await pool.query("INSERT INTO users (email, username, role) VALUES ('nepopoln@primer.si', 'nepopoln', 'business') RETURNING id")).rows[0].id;
    klubi.nepopoln = await klub("Nepopolni Klub", uNepopoln, { popoln: false });
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES ($1, $2, 'doorman')", [klubi.moj, U.vratar]);
    await pool.query("INSERT INTO club_follows (user_id, club_id) VALUES ($1, $2)", [U.sledilec, klubi.moj]);
    const ZETON_NAPRAVE = crypto.createHash("sha256").update("objava-sledilec").digest("hex");
    let r = await api("POST", "/me/devices", T.sledilec, { token: ZETON_NAPRAVE, platform: "ios" });
    assert(r.status === 200, "sledilec registrira napravo", r.body);

    const ISO = (ms) => new Date(Date.now() + ms).toISOString();
    const URA = 3600e3, DAN = 24 * URA;
    const dogodek = async (klubId, naslov, polja = {}) => {
      const e = { status: "draft", start: ISO(10 * DAN), end: ISO(10 * DAN + 6 * URA), price: 0, publish: null, poster: "https://slike.test/p.jpg", ...polja };
      return (await pool.query(
        `INSERT INTO events (club_id, title, status, start_at, end_at, poster_url, ticket_price_cents, capacity, publish_at) VALUES ($1, $2, $3, $4, $5, $8, $6, 100, $7) RETURNING id`,
        [klubId, naslov, e.status, e.start, e.end, e.price, e.publish, e.poster])).rows[0].id;
    };
    const vrstica = async (id) => (await pool.query("SELECT status, publish_at FROM events WHERE id = $1", [id])).rows[0];
    const pat = (id, telo, tok = T.admin) => api("PATCH", `/events/${id}`, tok, telo);
    const dnevnik = async (id) => (await pool.query("SELECT dejanje, admin_user_id, prej, potem FROM admin_dejanja WHERE cilj_tip = 'event' AND cilj_id = $1 ORDER BY id", [String(id)])).rows;
    const casIso = (x) => (x ? x.toISOString() : null);

    // -----------------------------------------------------------------------------------------------------------------
    console.log("\n# P1 PATCH publishAt");
    const E = await dogodek(klubi.moj, "Osnutek z urnikom");
    const cas1 = ISO(2 * DAN);
    r = await pat(E, { publishAt: cas1 });
    assert(r.status === 200 && casIso((await vrstica(E)).publish_at) === cas1, "admin: publishAt v prihodnosti -> 200, shranjeno", [r.status, r.body]);
    assert(r.body && r.body.publish_at === cas1, "PATCH odgovor ima publish_at (ISO)", r.body && r.body.publish_at);
    const dn1 = await dnevnik(E);
    assert(dn1.length === 1 && dn1[0].dejanje === "event.update" && dn1[0].prej.publish_at === null && dn1[0].potem.publish_at === cas1 && Object.keys(dn1[0].potem).join() === "publish_at",
      "admin_dejanja: event.update, prej null, potem cas, samo spremenjeno polje", dn1);
    const cas2 = ISO(3 * DAN);
    r = await pat(E, { publish_at: cas2 });
    assert(r.status === 200 && casIso((await vrstica(E)).publish_at) === cas2, "snake_case publish_at deluje", r.status);
    r = await pat(E, { title: "Osnutek z urnikom (preimenovan)" });
    assert(r.status === 200 && casIso((await vrstica(E)).publish_at) === cas2, "PATCH brez publishAt: cas ostane (obrazci iOS/splet ga ne poznajo)");
    r = await pat(E, { publishAt: cas2 });
    assert(r.status === 200 && (await dnevnik(E)).filter((x) => x.potem && "publish_at" in x.potem).length === 2, "ista vrednost: 200, brez nove vrstice dnevnika");
    r = await pat(E, { publishAt: null });
    assert(r.status === 200 && (await vrstica(E)).publish_at === null && r.body.publish_at === null, "publishAt null = preklic");
    assert((await dnevnik(E)).slice(-1)[0].potem.publish_at === null, "preklic je v dnevniku (potem null)");
    r = await pat(E, { publishAt: null });
    assert(r.status === 200 || r.status === 400, "ponovni preklic ne da 500", r.status);
    // vloge
    r = await pat(E, { publishAt: cas1 }, T.lastnik);
    assert(r.status === 200 && casIso((await vrstica(E)).publish_at) === cas1, "lastnik kluba sme nastaviti (kot ostala polja)");
    r = await pat(E, { publishAt: cas2 }, T.tuj);
    assert(r.status === 403 && casIso((await vrstica(E)).publish_at) === cas1, "tuj lastnik 403, vrednost nespremenjena");
    r = await pat(E, { publishAt: cas2 }, T.vratar);
    assert(r.status === 403, "vratar 403");
    r = await pat(E, { publishAt: cas2 }, T.kupec);
    assert(r.status === 403, "navaden uporabnik 403");
    r = await pat(E, { publishAt: cas2 }, null);
    assert(r.status === 401, "brez zetona 401");
    assert((await dnevnik(E)).every((x) => x.admin_user_id !== null), "admin_dejanja: vrstice samo za admina (lastnik vrstice ne ustvari)");
    // formati
    const slab = [["niz", "abc"], ["stevilo", 1735689600], ["prazen niz", ""], ["brez obmocja", "2030-01-01T10:00:00"], ["31. 2.", "2030-02-31T10:00:00Z"], ["leto 1999", "1999-01-01T10:00:00Z"], ["objekt", {}], ["true", true]];
    for (const [ime, v] of slab) {
      r = await pat(E, { publishAt: v });
      assert(r.status === 400 && casIso((await vrstica(E)).publish_at) === cas1, `neveljaven zapis (${ime}) -> 400, vrednost nespremenjena`, [r.status, r.besedilo && r.besedilo.slice(0, 80)]);
    }
    // pred zacetkom
    const zacE = (await pool.query("SELECT start_at FROM events WHERE id = $1", [E])).rows[0].start_at.toISOString();
    r = await pat(E, { publishAt: zacE });
    assert(r.status === 400 && r.body.error === "invalid_publish_at", "publishAt = zacetek -> 400 invalid_publish_at", r.body);
    r = await pat(E, { publishAt: ISO(11 * DAN) });
    assert(r.status === 400 && r.body.error === "invalid_publish_at" && casIso((await vrstica(E)).publish_at) === cas1, "publishAt po zacetku -> 400, nespremenjeno", r.body);
    r = await pat(E, { publishAt: ISO(11 * DAN), startAt: ISO(12 * DAN), endAt: ISO(12 * DAN + 6 * URA) });
    assert(r.status === 200, "publishAt po STAREM zacetku, a pred NOVIM (isti zahtevek) -> 200", [r.status, r.body]);
    r = await pat(E, { publishAt: ISO(-5 * 60e3) });
    assert(r.status === 200, "publishAt v preteklosti je dovoljen (objavi se v naslednjem krogu)", r.status);
    // delavec ga objavi: pocakaj in preveri, da je bila objava edina sprememba
    assert(await pocakaj(async () => (await vrstica(E)).status === "published"), "delavec objavi osnutek s casom v preteklosti (PATCH + delavec)");
    r = await pat(E, { publishAt: ISO(DAN) });
    assert(r.status === 400 && r.body.error === "not_a_draft", "objavljen dogodek: publishAt -> 400 not_a_draft", r.body);
    assert((await vrstica(E)).publish_at === null, "objavljen dogodek: publish_at ostane NULL");
    r = await pat(E, { publishAt: null });
    assert(r.status === 200, "objavljen dogodek: publishAt null (preklic) je brez ucinka, 200", r.status);
    // odpovedan
    const Eo = await dogodek(klubi.moj, "Odpovedan z urnikom", { status: "cancelled" });
    r = await pat(Eo, { publishAt: ISO(DAN) });
    assert(r.status === 400 && r.body.error === "not_a_draft" && (await vrstica(Eo)).publish_at === null, "odpovedan dogodek: publishAt -> 400");
    // stanje + publishAt v istem zahtevku
    const Es = await dogodek(klubi.moj, "Stanje in cas");
    r = await pat(Es, { status: "published", publishAt: ISO(DAN) });
    assert(r.status === 400 && r.body.error === "not_a_draft" && (await vrstica(Es)).status === "draft", "status published + publishAt v istem zahtevku -> 400, nic se ne spremeni");
    r = await pat(Es, { status: "draft", publishAt: ISO(DAN) });
    assert(r.status === 200 && (await vrstica(Es)).publish_at !== null, "status draft + publishAt -> 200");
    // sprememba stanja pobrise cas
    r = await pat(Es, { status: "published" });
    assert(r.status === 200 && (await vrstica(Es)).publish_at === null, "rocna objava (PATCH status published) pobrise nacrtovani cas");
    await pool.query("UPDATE events SET publish_at = NOW() - INTERVAL '2 hours' WHERE id = $1", [Es]);   // zastarel cas na objavljenem dogodku (npr. zaostanek iz stare vrstice)
    r = await pat(Es, { status: "draft" });
    assert(r.status === 200 && (await vrstica(Es)).publish_at === null && (await vrstica(Es)).status === "draft", "»Med osnutke« pobrise zastarel cas: osnutek ne skoci takoj nazaj v objavo");
    r = await pat(Es, { status: "draft", title: "Se vedno osnutek" });
    assert(r.status === 200 && (await vrstica(Es)).status === "draft", "osnutek brez casa ostane osnutek");
    await pat(Es, { publishAt: ISO(DAN) });
    r = await api("PATCH", `/admin/api/events/${Es}`, T.admin, { status: "published" });
    assert(r.status === 200 && (await vrstica(Es)).publish_at === null, "admin pot PATCH /admin/api/events/:id (Objavi vseeno) pobrise nacrtovani cas");
    r = await api("PATCH", `/admin/api/events/${Es}`, T.admin, { status: "draft" });
    assert(r.status === 200 && (await vrstica(Es)).publish_at === null && (await vrstica(Es)).status === "draft", "admin pot: nazaj med osnutke, cas ostane NULL");
    // odpoved pobrise
    await pat(Es, { publishAt: ISO(DAN) });
    r = await pat(Es, { status: "cancelled" });
    assert(r.status === 200 && (await vrstica(Es)).publish_at === null, "odpoved pobrise nacrtovani cas");

    // -----------------------------------------------------------------------------------------------------------------
    console.log("\n# P2 odgovori: admin ima publish_at, javni ne");
    const Ep = await dogodek(klubi.moj, "Javni odgovori", { publish: ISO(5 * DAN) });
    r = await api("GET", `/admin/api/events/${Ep}`, T.admin);
    assert(r.status === 200 && r.body.event.publish_at === (await vrstica(Ep)).publish_at.toISOString(), "GET /admin/api/events/:id: event.publish_at", r.body.event && r.body.event.publish_at);
    r = await api("GET", "/admin/api/events", T.admin);
    const vSeznamu = Array.isArray(r.body) && r.body.find((x) => x.id === Ep);
    assert(r.status === 200 && vSeznamu && vSeznamu.publish_at === (await vrstica(Ep)).publish_at.toISOString() && "publish_at" in r.body[0], "GET /admin/api/events: vsaka vrstica ima publish_at (dodano polje)");
    // javno: objavljen dogodek s tujim (zastarelim) publish_at vseeno ne razkrije polja
    const Ej = await dogodek(klubi.moj, "Objavljen s starim casom", { status: "published" });
    await pool.query("UPDATE events SET publish_at = NOW() + INTERVAL '3 days' WHERE id = $1", [Ej]);
    for (const [ime, pot, tok] of [["GET /events/:id", `/events/${Ej}`, undefined], ["GET /events", "/events", undefined], ["GET /events/:id (prijavljen)", `/events/${Ej}`, T.kupec],
      ["GET /clubs/:id/events", `/clubs/${klubi.moj}/events`, undefined], ["GET /business/events", "/business/events", T.lastnik], ["GET /search", "/search?q=Objavljen", undefined]]) {
      const odg = await api("GET", pot, tok);
      assert(odg.status !== 500 && !/publish_at|publishAt/i.test(odg.besedilo), `${ime}: brez publish_at (${odg.status})`, odg.besedilo && odg.besedilo.slice(0, 100));
    }
    r = await api("GET", `/events/${Ej}`);
    assert(r.status === 200 && r.body.id === Ej, "pozitivna kontrola: GET /events/:id objavljenega dogodka -> 200", r.status);
    await pool.query("UPDATE events SET publish_at = NULL WHERE id = $1", [Ej]);

    // -----------------------------------------------------------------------------------------------------------------
    console.log("\n# P3 dva procesa: ena objava, en push; kar se ne sme objaviti, se ne");
    await pool.query("DELETE FROM events WHERE id IN ($1, $2)", [Ep, Ej]);
    const Eprih = await dogodek(klubi.moj, "V prihodnosti", { publish: ISO(2 * DAN) });
    const Epreklic = await dogodek(klubi.moj, "Preklican urnik", { publish: ISO(2 * DAN) });
    r = await pat(Epreklic, { publishAt: null });
    assert(r.status === 200 && (await vrstica(Epreklic)).publish_at === null, "preklic urnika pred potekom: 200, cas NULL");
    const Eodp = await dogodek(klubi.moj, "Odpovedan s casom", { status: "cancelled", publish: ISO(-60e3) });
    const Ezac = await dogodek(klubi.moj, "Zacet s casom", { start: ISO(-30 * 60e3), end: ISO(5 * URA), publish: ISO(-60e3) });
    const Etek = await dogodek(klubi.moj, "Tekmovalni", { publish: ISO(-60e3) });
    assert(await pocakaj(async () => (await vrstica(Etek)).status === "published"), "dogodek s casom v preteklosti objavljen");
    assert((await vrstica(Ezac)).status === "draft" && (await vrstica(Ezac)).publish_at !== null, "dogodek, ki se je ze zacel, ni kandidat: ostane osnutek (z casom, za rocno odlocitev); modulni test M4 preveri, da ne zaseda kroga");
    const x = await vrstica(Etek);
    assert(x.publish_at === null, "po objavi publish_at = NULL");
    const dn3 = (await dnevnik(Etek)).filter((v) => v.dejanje === "event.publish_auto");
    assert(dn3.length === 1 && dn3[0].admin_user_id === null && dn3[0].prej.status === "draft" && dn3[0].potem.status === "published", "natanko ena vrstica event.publish_auto brez admina (dva procesa)", dn3);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications WHERE event_id = $1", [Etek])).rows[0].n === 1, "sledilec dobi natanko eno obvestilo v zvoncu");
    assert(await pocakaj(() => pushiZa(Etek).length >= 1), "push sledilcu je prispel na APNs");
    // zapornik: naslednja objava + njen push; sele nato je »natanko en push« za prejsnjo trdno
    const Ezap = await dogodek(klubi.moj, "Zapornik", { publish: ISO(-60e3) });
    assert(await pocakaj(async () => (await vrstica(Ezap)).status === "published" && pushiZa(Ezap).length >= 1), "zapornik objavljen in push prispel");
    assert(pushiZa(Etek).length === 1 && pushiZa(Etek)[0].zeton === ZETON_NAPRAVE, "natanko en push za dogodek (dva procesa)", pushiZa(Etek).length);
    assert((await vrstica(Eprih)).status === "draft" && (await vrstica(Epreklic)).status === "draft" && (await vrstica(Epreklic)).publish_at === null, "prihodnji in preklicani urnik: nic se ni zgodilo");
    assert((await vrstica(Eodp)).status === "cancelled" && (await dnevnik(Eodp)).length === 0, "odpovedan dogodek se ne objavi (in ni vrstice dnevnika)");
    // javni vpogled po objavi
    r = await api("GET", `/events/${Etek}`);
    assert(r.status === 200 && r.body.id === Etek && !/publish_at/i.test(r.besedilo), "objavljeni dogodek je javno viden brez publish_at", r.status);
    assert(vLogu(`dogodek ${Etek} objavljen`), "dnevnik procesa: »dogodek N objavljen«");

    // -----------------------------------------------------------------------------------------------------------------
    console.log("\n# P4 push pade, obvestilo pade: dogodek ostane objavljen (I29)");
    rezimApns = "500";
    const E500 = await dogodek(klubi.moj, "APNs 500", { publish: ISO(-60e3) });
    assert(await pocakaj(async () => (await vrstica(E500)).status === "published"), "APNs vrača 500: dogodek objavljen");
    assert(await pocakaj(() => pushiZa(E500).length >= 1), "push je bil poskusen (APNs 500)");
    assert((await vrstica(E500)).status === "published" && (await dnevnik(E500)).filter((v) => v.dejanje === "event.publish_auto").length === 1, "po neuspelem pushu dogodek ostane objavljen, dnevnik je zapisan");
    rezimApns = "ok";
    await sprozilec(`CREATE OR REPLACE FUNCTION t_objava_pade() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'test: obvestilo pade'; END $$ LANGUAGE plpgsql`);
    await sprozilec("CREATE TRIGGER t_objava_pade BEFORE INSERT ON club_event_notifications FOR EACH ROW EXECUTE FUNCTION t_objava_pade()");
    let Enf;
    try {
      Enf = await dogodek(klubi.moj, "Obvestilo pade", { publish: ISO(-60e3) });
      assert(await pocakaj(async () => (await vrstica(Enf)).status === "published"), "vstavljanje obvestil pade: dogodek vseeno objavljen");
      assert(await pocakaj(() => vLogu("obvestilo po objavi ni uspelo")), "napaka obvestila je v dnevniku procesa (ne podre delavca)");
    } finally { await sprozilec("DROP TRIGGER IF EXISTS t_objava_pade ON club_event_notifications"); }
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications WHERE event_id = $1", [Enf])).rows[0].n === 0 && (await vrstica(Enf)).status === "published", "brez obvestil, a objavljen");
    // delavec se po napaki obnese
    const Epo = await dogodek(klubi.moj, "Po napaki", { publish: ISO(-60e3) });
    assert(await pocakaj(async () => (await vrstica(Epo)).status === "published" && pushiZa(Epo).length >= 1), "po napaki delavec dela naprej (objava + push)");

    // -----------------------------------------------------------------------------------------------------------------
    console.log("\n# P5 isti pogoji kot rocna objava: rdeca ovira = osnutek + rdece opozorilo");
    const Ered = await dogodek(klubi.nepopoln, "Rdeca ovira", { price: 1500, publish: ISO(-10 * 60e3) });
    r = await api("GET", `/admin/api/opozorila?dogodek=${Ered}`, T.admin);
    assert(r.status === 200 && r.body.stevci.rdece === 1 && r.body.items.some((i) => i.vrsta === "prodajalec_nepopoln"), "pregled pred objavo za dogodek: rdeca ovira prodajalec_nepopoln (pogoj panela)", r.body);
    assert(!r.body.items.some((i) => i.vrsta === "objava_zamujena"), "pregled ENEGA dogodka nima vrstice objava_zamujena (sicer bi sama blokirala rocno objavo)");
    assert(await pocakaj(() => vLogu(`dogodek ${Ered} ostane osnutek: rdeca ovira pred objavo (prodajalec_nepopoln)`)), "delavec je dogodek pregledal in ga pustil kot osnutek (dnevnik procesa)");
    assert((await vrstica(Ered)).status === "draft" && (await vrstica(Ered)).publish_at !== null, "rdeca ovira: osnutek ostane in nacrtovani cas ostane");
    r = await api("GET", "/admin/api/opozorila", T.admin);
    const zam = r.body.items.filter((i) => i.vrsta === "objava_zamujena");
    assert(r.status === 200 && zam.length === 1 && zam[0].resnost === "rdece" && zam[0].cilj_tip === "dogodek" && zam[0].cilj_id === Ered && /samodejna objava/i.test(zam[0].besedilo), "GET /admin/api/opozorila: rdece objava_zamujena za ta dogodek", zam);
    assert(r.body.stevci.rdece >= 1, "stevec rdecih opozoril ga steje", r.body.stevci);
    const Eza = await dogodek(klubi.moj, "Ravno potekel", { publish: ISO(-30e3) });   // manj kot 3 min po roku: se ni zamuda (delavec ga objavi v sekundi)
    assert(await pocakaj(async () => (await vrstica(Eza)).status === "published"), "navaden dogodek v istem casu je objavljen");
    // ovira izgine -> objavi se
    await pool.query("UPDATE clubs SET legal_name = 'Klub d.o.o.', legal_address = 'Ulica 1, 1000 Ljubljana', registration_number = '1234567', tax_number = 'SI12345678', vat_payer = TRUE, contact_email = 'info@klub.si' WHERE id = $1", [klubi.nepopoln]);
    // klub se nima Stripa -> placila_niso_pripravljena je prav tako rdeca ovira; dokler je, ostane osnutek
    r = await api("GET", `/admin/api/opozorila?dogodek=${Ered}`, T.admin);
    const ostaja = r.body.stevci.rdece > 0;
    if (ostaja) {
      assert(r.body.items.some((i) => i.vrsta === "placila_niso_pripravljena" && i.resnost === "rdece"), "po popravku podatkov klub brez Stripa: placila_niso_pripravljena je rdeca ovira", r.body.items);
      assert((await vrstica(Ered)).status === "draft", "dokler je katerakoli rdeca ovira, osnutek ostane");
      await pool.query("UPDATE clubs SET stripe_account_id = 'acct_popravljen', stripe_charges_enabled = TRUE, stripe_payouts_enabled = TRUE, stripe_account_livemode = TRUE WHERE id = $1", [klubi.nepopoln]);
    }
    assert(await pocakaj(async () => (await vrstica(Ered)).status === "published"), "ko rdeca ovira izgine, se dogodek objavi v naslednjem krogu");
    r = await api("GET", "/admin/api/opozorila", T.admin);
    assert(!r.body.items.some((i) => i.vrsta === "objava_zamujena" && i.cilj_id === Ered), "po objavi opozorila objava_zamujena ni vec");
    // osnutek, ki se je zacel in je zamudil: rdece opozorilo; preklic casa ga odstrani
    await pool.query("UPDATE events SET publish_at = NOW() - INTERVAL '30 minutes' WHERE id = $1", [Ezac]);
    r = await api("GET", "/admin/api/opozorila", T.admin);
    assert(r.body.items.some((i) => i.vrsta === "objava_zamujena" && i.cilj_id === Ezac && i.resnost === "rdece"), "osnutek, ki se je zacel: rdece objava_zamujena");
    await pat(Ezac, { publishAt: null });
    r = await api("GET", "/admin/api/opozorila", T.admin);
    assert(!r.body.items.some((i) => i.vrsta === "objava_zamujena" && i.cilj_id === Ezac), "po preklicu casa opozorila ni");

    // skriti klub: opozorilo objava_zamujena se vseeno pokaze (admin ga mora videti), druga opozorila skritega kluba ne
    const uSkrit = (await pool.query("INSERT INTO users (email, username, role) VALUES ('skrit@primer.si', 'skritlastnik', 'business') RETURNING id")).rows[0].id;
    klubi.skrit = await klub("Skriti Klub", uSkrit, { popoln: false });
    await pool.query("UPDATE clubs SET hidden = TRUE WHERE id = $1", [klubi.skrit]);
    const Eskrit = await dogodek(klubi.skrit, "Skriti osnutek", { price: 1500, publish: ISO(-10 * 60e3), poster: "", start: ISO(3 * DAN), end: ISO(3 * DAN + 6 * URA) });
    assert(await pocakaj(() => vLogu(`dogodek ${Eskrit} ostane osnutek: rdeca ovira`)), "skriti klub: delavec ga pregleda in pusti kot osnutek");
    r = await api("GET", "/admin/api/opozorila", T.admin);
    const zs = r.body.items.filter((i) => i.cilj_id === Eskrit);
    assert(zs.length === 1 && zs[0].vrsta === "objava_zamujena" && zs[0].resnost === "rdece", "skriti klub: objava_zamujena je v opozorilih (druga opozorila skritega kluba ne)", zs);
    // odpoved z narocili (DELETE /events/:id) pobrise nacrtovani cas
    const Edel = await dogodek(klubi.moj, "Odpoved z narocilom", { publish: ISO(2 * DAN) });
    await pool.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email)
       VALUES ('OUT-OBJ-1', $1, $2, $3, 1, 0, 0, 'pending', 'kupec@primer.si')`, [U.kupec, Edel, klubi.moj]);
    r = await api("DELETE", `/events/${Edel}`, T.admin);
    assert(r.status === 200 && (await vrstica(Edel)).status === "cancelled" && (await vrstica(Edel)).publish_at === null, "DELETE z narocili (odpoved) pobrise nacrtovani cas", [r.status, await vrstica(Edel)]);

    // -----------------------------------------------------------------------------------------------------------------
    console.log("\n# P6 javni predpomnilnik: objava je takoj vidna (razveljavitev, ne TTL)");
    for (const o of procesi) o.proc.kill();
    await cakaj(300);
    procesi.length = 0;
    p3 = zazeniBackend(PORT3, { JAVNI_PREDPOMNILNIK_MS: "60000" });
    assert(await cakajNaStrezbo(BASE3), "backend s predpomnilnikom 60 s se je zagnal");
    await pool.query("UPDATE events SET publish_at = NULL WHERE status = 'draft'");
    const Epred = await dogodek(klubi.moj, "Predpomnilnik", { publish: ISO(2 * DAN) });
    r = await apiNa(BASE3, "GET", "/events");
    assert(r.status === 200 && !JSON.stringify(r.body).includes('"Predpomnilnik"'), "javni seznam brez osnutka (zdaj je v predpomnilniku 60 s)");
    await pool.query("UPDATE events SET publish_at = NOW() - INTERVAL '1 second' WHERE id = $1", [Epred]);
    assert(await pocakaj(async () => (await vrstica(Epred)).status === "published"), "delavec objavi");
    r = await apiNa(BASE3, "GET", "/events");
    assert(r.status === 200 && JSON.stringify(r.body).includes('"Predpomnilnik"'), "javni seznam takoj po objavi ima dogodek (predpomnilnik 60 s je bil razveljavljen)");
    r = await apiNa(BASE3, "GET", `/events/${Epred}`);
    assert(r.status === 200 && r.body.id === Epred, "GET /events/:id takoj po objavi je 200", r.status);
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA", e && e.stack || e);
  } finally {
    try { await pool.query("DROP TRIGGER IF EXISTS t_objava_pade ON club_event_notifications"); } catch (_) { /* ni baze */ }
    for (const o of procesi) { try { o.proc.kill(); } catch (_) { /* ze mrtev */ } }
    try { await lock.end(); await lock2.end(); await pool.end(); } catch (_) { /* ignore */ }
    jwksServer.close(); apnsStreznik.close();
    try { fs.rmSync(mapa, { recursive: true, force: true }); } catch (_) { /* ignore */ }
    console.log(`\n${ok} OK, ${fail} napak`);
    if (fail) { for (const o of procesi) console.log("--- log procesa (zadnjih 1500 znakov) ---\n" + o.log.slice(-1500)); }
    process.exit(fail ? 1 : 0);
  }
})();
