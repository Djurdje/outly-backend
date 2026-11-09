#!/usr/bin/env node
/**
 * Zabelezen prenos seznama za sken brez povezave + opozorilo `sken_ni_pripravljen` (#406, migracija 075, I71).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres@localhost:5432/outly node _testi/test_sken_prenos.js
 *
 *   P1  uspesen GET scan-list -> vrstica v sken_prenosi (event_id, club_id, zadnji_prenos, prenosov = 1; tabela brez osebnih stolpcev)
 *   P2  drugi klic znotraj 60 s -> brez novega zapisa (prenosov ostane 1); po izteku razmika (SKEN_PRENOS_RAZMIK_MS) se zapise (prenosov = 2)
 *   P3  304 (If-None-Match) steje kot prenos; neuspel scan-list (403 brez vloge v klubu, 404 tuj/neobstojec dogodek, 400 neveljaven id) -> brez zapisa
 *   P4  opozorilo sken_ni_pripravljen: dogodek cez 1 h z veljavno vstopnico brez prenosa -> oranzno; izgine po prenosu; guest lista (placano narocilo) steje;
 *       brez opozorila: dogodek cez 5 h, brez vstopnic, osnutek, ze koncan, skrit klub, prenos starejsi od 24 h = opozorilo spet
 *   P5  sken (POST /business/tickets/scan) deluje, ko je sken_prenosi zaklenjena (ACCESS EXCLUSIVE iz druge seje); scan-list odgovor ni zadrzan;
 *       zapis po izteku lock_timeout odpade samo z opozorilom v dnevniku (brez POZOR, brez 500), proces tece
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6441, JWKS_PORT = 6442;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-sken-prenos";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});
function b64u(o) { return Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url"); }
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, path, token, body, glave = {}, rokMs = 15000) {
  const t0 = Date.now();
  try {
    const r = await fetch(BASE + path, {
      method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(rokMs),
    });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j, etag: r.headers.get("etag"), ms: Date.now() - t0 };
  } catch (e) { return { status: "visi", body: String(e.message), ms: Date.now() - t0 }; }
}

let srv = null, log = "";
async function zagon(okolje = {}) {
  log = "";
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    REZERVACIJE_CISCENJE_MS: "0", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 100; i++) { try { await fetch(BASE + "/"); return; } catch { await spi(100); } }
  throw new Error("backend se ni zagnal");
}
async function ustavi() { if (!srv) return; const s = srv; srv = null; if (s.exitCode !== null) return; await new Promise((r) => { s.once("exit", r); s.kill(); }); }

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE sken_prenosi, admin_dejanja, agent_zetoni, omejitve, table_service, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  try {
    await zagon();
    const T = { admin: zeton("admin@outly.si", uuid(1)), lastnik: zeton("lastnik@outly.si", uuid(2)), ana: zeton("ana@outly.si", uuid(3)), drug: zeton("drug@outly.si", uuid(4)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','drug@outly.si')");
    const uid = async (e) => (await pool.query("SELECT id FROM users WHERE email=$1", [e])).rows[0].id;
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Prenos Klub', 'Ljubljana')", [await uid("lastnik@outly.si")]);
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Tuj Klub', 'Maribor')", [await uid("drug@outly.si")]);
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, hidden) VALUES ($1, 'Skrit Klub', 'Celje', true)", [await uid("lastnik@outly.si")]);

    // Dogodki prek API-ja (brezplacni, da nastanejo placana narocila in vstopnice); cas se nato nastavi neposredno.
    // Vstopnice se kupijo, dokler je dogodek v prihodnosti; cas se nato nastavi neposredno (nakup po zacetku je zavrnjen).
    const serijske = {};
    const dogodek = async (klubId, naslov, token, startSql, endSql = "NULL", stVstopnic = 0) => {
      const r = await api("POST", "/events", token, { clubId: klubId, title: naslov, startAt: new Date(Date.now() + 7 * 864e5).toISOString(), ticketPriceCents: 0, capacity: 100, minAge: 0 });
      if (r.status !== 201) throw new Error("dogodek " + naslov + ": " + JSON.stringify(r.body));
      if (stVstopnic > 0) {
        const n = await api("POST", `/events/${r.body.id}/orders`, T.ana, { quantity: stVstopnic });
        if (n.status !== 201) throw new Error("naročilo: " + JSON.stringify(n.body));
        serijske[r.body.id] = n.body.tickets.map((t) => t.serial);
      }
      await pool.query(`UPDATE events SET start_at = ${startSql}, end_at = ${endSql} WHERE id=$1`, [r.body.id]);
      await pool.query("UPDATE tickets SET created_at = NOW() - INTERVAL '2 days' WHERE event_id=$1", [r.body.id]);
      return r.body.id;
    };
    const E = {};
    E.kmalu = await dogodek(1, "Cez eno uro", T.lastnik, "NOW() + INTERVAL '1 hour'", "NOW() + INTERVAL '7 hours'", 2);
    E.tece = await dogodek(1, "Ze tece", T.lastnik, "NOW() - INTERVAL '1 hour'", "NOW() + INTERVAL '5 hours'", 2);
    const serTece = serijske[E.tece];
    E.daleko = await dogodek(1, "Cez pet ur", T.lastnik, "NOW() + INTERVAL '5 hours'", "NOW() + INTERVAL '11 hours'", 2);
    E.brez = await dogodek(1, "Brez vstopnic", T.lastnik, "NOW() + INTERVAL '1 hour'", "NOW() + INTERVAL '7 hours'");
    E.osnutek = await dogodek(1, "Osnutek", T.lastnik, "NOW() + INTERVAL '1 hour'", "NOW() + INTERVAL '7 hours'", 2);
    await pool.query("UPDATE events SET status='draft' WHERE id=$1", [E.osnutek]);
    E.koncan = await dogodek(1, "Ze koncan", T.lastnik, "NOW() - INTERVAL '8 hours'", "NOW() - INTERVAL '2 hours'", 2);
    E.tuj = await dogodek(2, "Tuj dogodek", T.drug, "NOW() + INTERVAL '3 hours'", "NOW() + INTERVAL '9 hours'");
    E.guest = await dogodek(1, "Samo guest lista", T.lastnik, "NOW() + INTERVAL '90 minutes'", "NOW() + INTERVAL '8 hours'");
    // Guest lista: placano narocilo z guest_list_id in vstopnica (kot v index.js); brez nakupa kupca.
    {
      const lastnikId = await uid("lastnik@outly.si");
      const gl = await pool.query("INSERT INTO guest_lists (event_id, host_user_id, spots) VALUES ($1, $2, 1) RETURNING id", [E.guest, lastnikId]);
      {
        const or = await pool.query(
          `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, buyer_email, paid_at, guest_list_id)
           VALUES ($4::text, $2, $1, 1, 1, 0, 0, 'eur', 0, 'paid', 'lastnik@outly.si', NOW(), $3) RETURNING id`, [E.guest, lastnikId, gl.rows[0].id, "GL" + E.guest + "X" + Date.now()]);
        await pool.query("INSERT INTO tickets (order_id, event_id, holder_user_id) VALUES ($1, $2, $3)", [or.rows[0].id, E.guest, lastnikId]);
      }
    }
    const prenosi = async () => (await pool.query("SELECT event_id, club_id, zadnji_prenos, prenosov FROM sken_prenosi ORDER BY event_id")).rows;
    const vrstica = async (id) => (await pool.query("SELECT event_id, club_id, zadnji_prenos, prenosov FROM sken_prenosi WHERE event_id=$1", [id])).rows[0];
    const cakaj = async (pogoj, ms = 4000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await pogoj()) return true; await spi(60); } return false; };
    const opozorila = async () => (await api("GET", "/admin/api/opozorila", T.admin)).body;
    const sken = (o) => o.items.filter((x) => x.vrsta === "sken_ni_pripravljen").map((x) => x.cilj_id);

    // ------------------------------------------------------------ P0: brez prenosa
    console.log("\n# P0: izhodisce, nihce ni prenesel seznama");
    assert((await prenosi()).length === 0, "sken_prenosi je prazna");
    const stolpci = (await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='sken_prenosi' ORDER BY ordinal_position")).rows.map((x) => x.column_name);
    assert(JSON.stringify(stolpci) === JSON.stringify(["event_id", "club_id", "zadnji_prenos", "prenosov"]), "tabela nima osebnih stolpcev (user_id, device_id, ip)", stolpci);

    // ------------------------------------------------------------ P4a: opozorilo pred prenosom
    console.log("\n# P4a: opozorilo sken_ni_pripravljen pred prenosom");
    let o = await opozorila();
    const ids = sken(o);
    assert(ids.includes(E.kmalu), "cez 1 h, veljavne vstopnice, brez prenosa -> oranzno opozorilo");
    assert(ids.includes(E.tece), "ze tece (ni koncan), brez prenosa -> opozorilo");
    assert(ids.includes(E.guest), "samo guest lista (placano narocilo z vstopnico) -> opozorilo");
    assert(!ids.includes(E.daleko), "cez 5 h -> brez opozorila");
    assert(!ids.includes(E.brez), "brez vstopnic -> brez opozorila");
    assert(!ids.includes(E.osnutek), "osnutek -> brez opozorila");
    assert(!ids.includes(E.koncan), "ze koncan -> brez opozorila");
    const op = o.items.find((x) => x.vrsta === "sken_ni_pripravljen" && x.cilj_id === E.kmalu);
    assert(op && op.resnost === "oranzno" && op.cilj_tip === "dogodek" && /Cez eno uro/.test(op.besedilo) && /noben telefon kluba/.test(op.besedilo), "oranzno, cilj dogodek, ime dogodka v besedilu", op);
    assert(!!op && !/@|ana@|\bana\b/i.test(op.besedilo), "besedilo je brez e-naslovov in imen uporabnikov");
    await pool.query("UPDATE clubs SET hidden=true WHERE id=1");
    assert(!sken(await opozorila()).includes(E.kmalu), "skriti klub -> brez opozorila");
    await pool.query("UPDATE clubs SET hidden=false WHERE id=1");

    // ------------------------------------------------------------ P3: neuspel scan-list brez zapisa
    console.log("\n# P3a: neuspel scan-list ne pusti sledi");
    let r = await api("GET", `/business/events/${E.kmalu}/scan-list`, T.ana);
    assert(r.status === 403, "ana (brez vloge v klubu) -> 403", r.status);
    r = await api("GET", `/business/events/${E.tuj}/scan-list`, T.lastnik);
    assert(r.status === 404, "dogodek tujega kluba -> 404", r.status);
    r = await api("GET", `/business/events/999999/scan-list`, T.lastnik);
    assert(r.status === 404, "neobstojec dogodek -> 404", r.status);
    r = await api("GET", `/business/events/abc/scan-list`, T.lastnik);
    assert(r.status === 400, "neveljaven id -> 400", r.status);
    r = await api("GET", `/business/events/${E.kmalu}/scan-list`);
    assert(r.status === 401, "brez zetona -> 401", r.status);
    await spi(400);
    assert((await prenosi()).length === 0, "po vseh neuspelih klicih sken_prenosi ostane prazna");

    // ------------------------------------------------------------ P1
    console.log("\n# P1: uspesen scan-list zapise prenos");
    const t0 = Date.now();
    r = await api("GET", `/business/events/${E.kmalu}/scan-list`, T.lastnik);
    assert(r.status === 200 && r.body.tickets.length === 2 && r.etag, "200, 2 vstopnici, ETag", r.status);
    const etag = r.etag;
    assert(await cakaj(async () => (await prenosi()).length === 1), "vrstica nastane po odgovoru (ogenj in pozabi)");
    let v = await vrstica(E.kmalu);
    assert(v && Number(v.club_id) === 1 && v.prenosov === 1 && new Date(v.zadnji_prenos).getTime() >= t0 - 2000, "event_id, club_id = 1, prenosov = 1, cas pravkar", v);
    const log1 = log;
    assert(!/\[sken\][^\n]*POZOR|nepricakovana napaka|zapis prenosa/.test(log1), "dnevnik brez [sken] POZOR, brez nepricakovane napake in brez napake zapisa");

    // ------------------------------------------------------------ P4b: opozorilo izgine
    console.log("\n# P4b: po prenosu opozorilo izgine (samo za ta dogodek)");
    o = await opozorila();
    assert(!sken(o).includes(E.kmalu), "dogodek s prenosom -> brez opozorila");
    assert(sken(o).includes(E.tece) && sken(o).includes(E.guest), "drugi dogodki brez prenosa ostanejo");
    await pool.query("UPDATE sken_prenosi SET zadnji_prenos = NOW() - INTERVAL '25 hours' WHERE event_id=$1", [E.kmalu]);
    assert(sken(await opozorila()).includes(E.kmalu), "prenos starejsi od 24 h ne steje -> opozorilo spet");
    await pool.query("UPDATE sken_prenosi SET zadnji_prenos = NOW() - INTERVAL '23 hours' WHERE event_id=$1", [E.kmalu]);
    assert(!sken(await opozorila()).includes(E.kmalu), "prenos pred 23 h steje -> brez opozorila");
    await pool.query("UPDATE sken_prenosi SET zadnji_prenos = NOW(), prenosov = 1 WHERE event_id=$1", [E.kmalu]);

    // ------------------------------------------------------------ P2 / P3b
    console.log("\n# P2: drugi klic znotraj 60 s ne zapise; 304 steje kot prenos");
    r = await api("GET", `/business/events/${E.kmalu}/scan-list`, T.lastnik);
    assert(r.status === 200, "drugi klic 200");
    await spi(500);
    v = await vrstica(E.kmalu);
    assert(v.prenosov === 1 && Date.now() - new Date(v.zadnji_prenos).getTime() < 15000 && (Date.now() - new Date(v.zadnji_prenos).getTime()) > -1000, "znotraj razmika prenosov ostane 1", v);
    r = await api("GET", `/business/events/${E.tece}/scan-list`, T.lastnik, null, { "if-none-match": "W/\"neveljaven\"" });
    assert(r.status === 200, "prvi klic za drug dogodek 200");
    const etag2 = r.etag;
    assert(await cakaj(async () => !!(await vrstica(E.tece))), "drug dogodek dobi svojo vrstico");
    await ustavi();
    await zagon({ SKEN_PRENOS_RAZMIK_MS: "3000" });   // svez proces: pomnilnik razmika je prazen, razmik 3 s
    await pool.query("DELETE FROM sken_prenosi WHERE event_id=$1", [E.tece]);
    r = await api("GET", `/business/events/${E.tece}/scan-list`, T.lastnik, null, { "if-none-match": etag2, "cache-control": "max-age=300" });
    assert(r.status === 304, "If-None-Match z veljavnim ETag -> 304", r.status);
    assert(await cakaj(async () => !!(await vrstica(E.tece))), "304 steje kot prenos (vrstica nastane)");
    assert((await vrstica(E.tece)).prenosov === 1, "prenosov = 1 po 304");
    r = await api("GET", `/business/events/${E.tece}/scan-list`, T.lastnik, null, { "if-none-match": etag2, "cache-control": "max-age=300" });
    assert(r.status === 304, "drugi 304");
    await spi(300);
    assert((await vrstica(E.tece)).prenosov === 1, "znotraj razmika drugi 304 ne zapise");
    await spi(3200);
    r = await api("GET", `/business/events/${E.tece}/scan-list`, T.lastnik, null, { "if-none-match": etag2, "cache-control": "max-age=300" });
    assert(await cakaj(async () => (await vrstica(E.tece)).prenosov === 2), "po izteku razmika se zapise (prenosov = 2)", await vrstica(E.tece));

    // ------------------------------------------------------------ P5: sken ni odvisen od tabele
    console.log("\n# P5: sken in scan-list med ACCESS EXCLUSIVE na sken_prenosi");
    await pool.query("DELETE FROM sken_prenosi WHERE event_id=$1", [E.kmalu]);
    await ustavi();
    await zagon();   // svez proces = prazen pomnilnik razmika
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("LOCK TABLE sken_prenosi IN ACCESS EXCLUSIVE MODE");
      const s = await api("POST", "/business/tickets/scan", T.lastnik, { serial: serTece[0] }, {}, 5000);
      assert(s.status === 200 && s.body.result === "ok" && s.ms < 1500, `POST /business/tickets/scan med zaklepom: 200 ok v ${s.ms} ms`, s);
      const l = await api("GET", `/business/events/${E.kmalu}/scan-list`, T.lastnik, null, {}, 5000);
      assert(l.status === 200 && l.ms < 1500, `scan-list med zaklepom: 200 v ${l.ms} ms (odgovor ni zadrzan)`, { status: l.status, ms: l.ms });
      const s2 = await api("POST", "/business/tickets/scan", T.lastnik, { serial: serTece[1] }, {}, 5000);
      assert(s2.status === 200 && s2.body.result === "ok", "drugi sken med zaklepom 200 ok", s2);
      await spi(1200);   // lock_timeout zapisa (500 ms) je potekel
      assert(/zapis prenosa seznama ni uspel/.test(log), "zapis je odpadel z opozorilom v dnevniku (lock_timeout)");
      assert(!/\[sken\][^\n]*POZOR|nepricakovana napaka/.test(log), "dnevnik brez [sken] POZOR / nepricakovane napake; napaka zapisa je console.warn (Sentry lovi samo console.error)");
      await c.query("ROLLBACK");
    } finally { await c.query("ROLLBACK").catch(() => {}); c.release(); }
    assert((await api("GET", "/healthz")).status === 200, "proces zdrav po izteku zapisa");
    assert((await prenosi()).filter((x) => x.event_id === E.kmalu).length === 0, "med zaklepom ni nastal zapis za dogodek");
    r = await api("GET", `/business/events/${E.kmalu}/scan-list`, T.lastnik);
    assert(r.status === 200, "po sprostitvi zaklepa scan-list 200");
    await spi(100);
    // razmik je ze porabljen (poskus je bil v pomnilniku zabelezen): naslednji zapis prek svezega procesa
    await ustavi(); await zagon();
    await api("GET", `/business/events/${E.kmalu}/scan-list`, T.lastnik);
    assert(await cakaj(async () => !!(await vrstica(E.kmalu))), "po sprostitvi zaklepa zapis spet deluje");

    // ------------------------------------------------------------ P6: evidenca migracije 075
    console.log("\n# P6: odtis in blok 075 v db/VSE_MIGRACIJE.sql ustrezata datoteki");
    const fs = require("fs"), path = require("path");
    const datoteka = fs.readFileSync(path.join(__dirname, "..", "db", "migracije", "075_sken_prenosi.sql"), "utf8");
    const vse = fs.readFileSync(path.join(__dirname, "..", "db", "VSE_MIGRACIJE.sql"), "utf8");
    const odtis = crypto.createHash("sha256").update(datoteka).digest("hex").slice(0, 16);   // kot odtis() v db/migrate.js
    assert(vse.includes(`('075_sken_prenosi.sql', '${odtis}')`), `vpis 075 v VSE_MIGRACIJE.sql ima odtis datoteke (${odtis})`);
    const blok = datoteka.replace(/^(BEGIN|COMMIT);\n/gm, "").replace(/\n+$/, "");
    assert(vse.includes(blok), "blok 075 v VSE_MIGRACIJE.sql je enak datoteki brez BEGIN/COMMIT");
    const evid = (await pool.query("SELECT odtis FROM schema_migrations WHERE datoteka='075_sken_prenosi.sql'")).rows[0];
    assert(evid && evid.odtis === odtis, "schema_migrations v bazi ima isti odtis", evid);
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
  } finally {
    await ustavi();
    jwksServer.close();
    await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
