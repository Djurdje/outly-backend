#!/usr/bin/env node
/**
 * Zasedenost diska baze: GET /healthz/baza + opozorilo `baza_disk` (baza_disk.js, I68; Render outly-db: disk 1 GB, autoscaling izklopljen).
 * Zagon (lokalno, PG16, prazna baza z migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_baza_disk.js
 *
 *   B1  brez zetona: 200 { ok: true, disk_pct: <celo stevilo> } (SAMO ta dva kljuca), Cache-Control no-store; disk_pct = round(pg_database_size / (BAZA_DISK_MB MiB) * 100)
 *   B2  disk_pct >= BAZA_DISK_OPOZORILO_PCT -> 503 { ok: false, disk_pct }; meja je vkljucna (pct = meja -> 503, meja + 1 -> 200); POZOR v logu najvec 1x na proces
 *   B3  predpomnilnik: 40 hkratnih + 10 zaporednih klicev = ENA poizvedba pg_database_size; po izteku BAZA_DISK_VELJA_MS (samo test) nova
 *   B4  baza nedosegljiva (promet izgine, povezave ostanejo odprte) -> 503 { ok: false, disk_pct: null } v ~3 s, proces tece, po okrevanju spet 200
 *   B5  baza je nedosegljiva ze ob zagonu -> 503 { ok: false, disk_pct: null }, proces tece
 *   B6  admin opozorila: baza_disk (rdece) SAMO nad mejo, besedilo samo z odstotkom; ni ga pod mejo; isto v /admin/api/danes (opozorila_rdeca)
 *   B7  enota: sočasni klici si delijo obljubo, uspeh se obdrzi, napaka ne dlje kot kratko, povezava ob roku se unici (release(true)), pozne povezave se ne izgubijo
 */
const crypto = require("crypto");
const http = require("http");
const net = require("net");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 3520;
const KID = "test-kid-baza-disk";
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
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

async function zazeni(port, dbUrl, dodatniEnv = {}) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, REZERVACIJE_CISCENJE_MS: "0", PORT: String(port), DATABASE_URL: dbUrl,
    SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0", ...dodatniEnv }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 100; i++) { try { await fetch(`http://127.0.0.1:${port}/`); break; } catch { await spi(100); } }
  return { srv, log: () => log, ustavi: () => new Promise((r) => { if (srv.exitCode !== null) return r(); srv.once("exit", r); srv.kill(); }) };
}
async function klic(port, pot, token, rokMs = 15000) {
  const t0 = Date.now();
  try {
    const r = await fetch(`http://127.0.0.1:${port}${pot}`, { headers: token ? { authorization: "Bearer " + token } : {}, signal: AbortSignal.timeout(rokMs) });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j, ms: Date.now() - t0, cache: r.headers.get("cache-control") };
  } catch (e) { return { status: "visi", body: String(e.message), ms: Date.now() - t0 }; }
}

// TCP posrednik pred bazo: steje poizvedbe pg_database_size ('Q' preprost stavek, 'P' Parse) in lahko odvrze ves promet (polodprt TCP).
function posrednik() {
  const st = { zamrznjeno: false, meritev: 0 };
  const srvP = net.createServer((odj) => {
    const u = new URL(DB);
    const gor = net.connect(Number(u.port) || 5432, u.hostname);
    let buf = Buffer.alloc(0), zagon = true;
    odj.on("data", (d) => {
      if (st.zamrznjeno) return;
      buf = Buffer.concat([buf, d]);
      if (zagon) {
        if (buf.length < 8 || buf.length < buf.readInt32BE(0)) return;
        const n = buf.readInt32BE(0);
        gor.write(buf); buf = buf.subarray(n); zagon = false;
      } else gor.write(d);
      for (;;) {
        if (buf.length < 5) break;
        const n = buf.readInt32BE(1); if (buf.length < n + 1) break;
        if ((buf[0] === 0x51 || buf[0] === 0x50) && buf.subarray(5, n + 1).toString("utf8").includes("pg_database_size")) st.meritev++;
        buf = buf.subarray(n + 1);
      }
    });
    gor.on("data", (d) => { if (!st.zamrznjeno) odj.write(d); });
    for (const x of [odj, gor]) { x.on("error", () => {}); x.on("close", () => { odj.destroy(); gor.destroy(); }); }
  });
  return new Promise((r) => srvP.listen(0, "127.0.0.1", () => {
    const u = new URL(DB); u.hostname = "localhost"; u.port = String(srvP.address().port);
    r({ url: u.toString(), st, zapri: () => srvP.close() });
  }));
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, table_service, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  const velikost = async () => Number((await pool.query("SELECT pg_database_size(current_database()) AS b")).rows[0].b);
  const PORT = 3521;

  // ---------------------------------------------------------------- B1
  console.log("# B1: GET /healthz/baza");
  let b = await zazeni(PORT, DB);
  let pct1;
  try {
    const pred = await velikost();
    const r = await klic(PORT, "/healthz/baza");
    const po = await velikost();
    assert(r.status === 200, "brez zetona -> 200", r);
    assert(r.body && r.body.ok === true && Number.isInteger(r.body.disk_pct), "telo { ok: true, disk_pct: celo stevilo }", r.body);
    assert(r.body && Object.keys(r.body).sort().join() === "disk_pct,ok", "SAMO kljuca ok in disk_pct (brez bajtov, tabel, drugih podatkov)", r.body);
    assert(r.cache === "no-store", "Cache-Control: no-store", r.cache);
    const pricakovano = [pred, po].map((x) => Math.round(x / (1024 * 1048576) * 100));
    assert(r.body && r.body.disk_pct >= Math.min(...pricakovano) && r.body.disk_pct <= Math.max(...pricakovano), `disk_pct = round(velikost / (1024 MiB) * 100) (${r.body && r.body.disk_pct}, pricakovano ${pricakovano})`);
    pct1 = r.body.disk_pct;
    assert(!/POZOR.*disk/i.test(b.log()), "pod mejo ni POZOR v logu");
  } finally { await b.ustavi(); }

  // ---------------------------------------------------------------- B2
  console.log("\n# B2: meja in POZOR");
  b = await zazeni(PORT, DB, { BAZA_DISK_MB: "1" });   // baza ima vec kot 1 MB -> disk_pct >= 100
  try {
    const r = await klic(PORT, "/healthz/baza");
    assert(r.status === 503, "BAZA_DISK_MB=1 -> 503", r);
    assert(r.body && r.body.ok === false && Number.isInteger(r.body.disk_pct) && r.body.disk_pct >= 100 && Object.keys(r.body).sort().join() === "disk_pct,ok", "telo { ok: false, disk_pct >= 100 } (samo dva kljuca)", r.body);
    assert(r.cache === "no-store", "Cache-Control: no-store tudi pri 503", r.cache);
    for (let i = 0; i < 3; i++) await klic(PORT, "/healthz/baza");
    await spi(200);
    const pozor = b.log().split("\n").filter((l) => /POZOR/.test(l) && /baza/i.test(l));
    assert(pozor.length === 1, `console.error z oznako POZOR natanko 1x ob vec klicih (${pozor.length})`, pozor);
    assert(pozor.length === 1 && /\d+ ?%/.test(pozor[0]) && !/postgres:\/\//.test(pozor[0]), "POZOR navaja odstotek, brez poverilnic", pozor[0]);
  } finally { await b.ustavi(); }
  // meja je vkljucna: disk_pct == OPOZORILO_PCT -> 503; OPOZORILO_PCT + 1 -> 200 (ob BAZA_DISK_MB=1024 je disk_pct majhen, a vsaj 1 ni nujno: uporabi MB, pri katerem je pct v sredini)
  const velik = await velikost();
  const mb = Math.max(1, Math.ceil(velik / 1048576 / 0.5));   // baza zasede ~50 %
  b = await zazeni(PORT, DB, { BAZA_DISK_MB: String(mb), BAZA_DISK_OPOZORILO_PCT: "100" });
  let p50;
  try {
    const r = await klic(PORT, "/healthz/baza");
    p50 = r.body && r.body.disk_pct;
    assert(r.status === 200 && p50 >= 40 && p50 <= 60, `BAZA_DISK_MB=${mb}: ~50 % pod mejo 100 -> 200`, r);
  } finally { await b.ustavi(); }
  b = await zazeni(PORT, DB, { BAZA_DISK_MB: String(mb), BAZA_DISK_OPOZORILO_PCT: String(p50) });
  try {
    const r = await klic(PORT, "/healthz/baza");
    assert(r.status === 503 && r.body.ok === false && r.body.disk_pct === p50, `disk_pct = meja (${p50}) -> 503 (meja je vkljucna)`, r);
  } finally { await b.ustavi(); }
  b = await zazeni(PORT, DB, { BAZA_DISK_MB: String(mb), BAZA_DISK_OPOZORILO_PCT: String(p50 + 1) });
  try {
    const r = await klic(PORT, "/healthz/baza");
    assert(r.status === 200 && r.body.ok === true && r.body.disk_pct === p50, `disk_pct = meja - 1 -> 200`, r);
  } finally { await b.ustavi(); }
  // neveljavne vrednosti okolja -> privzeto (1024 MB, 70 %)
  b = await zazeni(PORT, DB, { BAZA_DISK_MB: "abc", BAZA_DISK_OPOZORILO_PCT: "0" });
  try {
    const r = await klic(PORT, "/healthz/baza");
    assert(r.status === 200 && r.body.disk_pct === pct1, "neveljavni BAZA_DISK_MB / BAZA_DISK_OPOZORILO_PCT -> privzeti vrednosti", r);
  } finally { await b.ustavi(); }

  // ---------------------------------------------------------------- B3
  console.log("\n# B3: predpomnilnik (ena poizvedba)");
  let pp = await posrednik();
  b = await zazeni(PORT, pp.url);
  try {
    const vzporedni = await Promise.all(Array.from({ length: 40 }, () => klic(PORT, "/healthz/baza")));
    assert(vzporedni.every((r) => r.status === 200 && r.body.ok === true), "40 hkratnih klicev -> vsi 200");
    for (let i = 0; i < 10; i++) await klic(PORT, "/healthz/baza");
    assert(pp.st.meritev === 1, `40 hkratnih + 10 zaporednih klicev -> 1 poizvedba pg_database_size (izmerjeno ${pp.st.meritev})`);
  } finally { await b.ustavi(); }
  pp.st.meritev = 0;
  b = await zazeni(PORT, pp.url, { BAZA_DISK_VELJA_MS: "500" });
  try {
    await klic(PORT, "/healthz/baza"); await klic(PORT, "/healthz/baza");
    assert(pp.st.meritev === 1, `znotraj roka velja: 1 poizvedba (${pp.st.meritev})`);
    await spi(700);
    await klic(PORT, "/healthz/baza");
    assert(pp.st.meritev === 2, `po izteku roka nova poizvedba (${pp.st.meritev})`);
  } finally { await b.ustavi(); }
  // privzeti rok je 5 min
  b = await zazeni(PORT, pp.url);
  try {
    assert(/\[baza_disk\].*5 ?min|\[baza_disk\].*300000/.test(b.log()), "zagon izpise privzeti rok 5 min", b.log().split("\n").find((l) => l.includes("[baza_disk]")));
  } finally { await b.ustavi(); }

  // ---------------------------------------------------------------- B4
  console.log("\n# B4: baza ne odgovori (polodprt TCP)");
  pp.st.meritev = 0;
  b = await zazeni(PORT, pp.url, { BAZA_DISK_VELJA_MS: "400" });
  try {
    pp.st.zamrznjeno = true;
    const r = await klic(PORT, "/healthz/baza", null, 15000);
    assert(r.status === 503 && r.body && r.body.ok === false && r.body.disk_pct === null && Object.keys(r.body).sort().join() === "disk_pct,ok", "503 { ok: false, disk_pct: null }", r);
    assert(r.ms < 5000, `odgovor v < 5 s, ne visi (${r.ms} ms)`);
    assert((await klic(PORT, "/")).status === 200, "proces tece");
    pp.st.zamrznjeno = false;
    await spi(600);
    let r2 = null;
    for (let i = 0; i < 6; i++) { r2 = await klic(PORT, "/healthz/baza", null, 8000); if (r2.status === 200) break; await spi(500); }
    assert(r2 && r2.status === 200 && r2.body.ok === true, "po okrevanju spet 200", r2);
  } finally { pp.st.zamrznjeno = false; await b.ustavi(); }
  pp.zapri();

  // ---------------------------------------------------------------- B5
  console.log("\n# B5: baza nedosegljiva ze ob zagonu");
  b = await zazeni(3522, "postgres://postgres:postgres@localhost:1/outly");
  try {
    const r = await klic(3522, "/healthz/baza");
    assert(r.status === 503 && r.body && r.body.ok === false && r.body.disk_pct === null, "503 { ok: false, disk_pct: null }", r);
    assert(r.ms < 5000, `v < 5 s (${r.ms} ms)`);
    assert((await klic(3522, "/")).status === 200, "proces tece");
  } finally { await b.ustavi(); }

  // ---------------------------------------------------------------- B6
  console.log("\n# B6: opozorilo baza_disk (admin)");
  const admin = zeton("admin@outly.si", "00000000-0000-4000-8000-000000000001");
  const navaden = zeton("navaden@outly.si", "00000000-0000-4000-8000-000000000002");
  b = await zazeni(PORT, DB, { BAZA_DISK_MB: "1" });
  try {
    for (const t of [admin, navaden]) assert((await klic(PORT, "/me", t)).status === 200, "GET /me");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    const o = await klic(PORT, "/admin/api/opozorila", admin);
    const v = o.body && o.body.items ? o.body.items.filter((x) => x.vrsta === "baza_disk") : [];
    assert(o.status === 200 && v.length === 1, "nad mejo: natanko eno opozorilo baza_disk", o);
    assert(v[0] && v[0].resnost === "rdece", "resnost rdece", v[0]);
    assert(v[0] && /\d+ ?%/.test(v[0].besedilo) && !/\d{4,} ?(B|bajt|MB)/i.test(v[0].besedilo), "besedilo ima odstotek, brez bajtov", v[0] && v[0].besedilo);
    assert(v[0] && Object.keys(v[0]).sort().join() === "besedilo,cilj_id,cilj_tip,resnost,vrsta", "polja samo kot ostala opozorila", v[0] && Object.keys(v[0]));
    const d = await klic(PORT, "/admin/api/danes", admin);
    assert(d.status === 200 && d.body.opozorila_rdeca >= 1, "/admin/api/danes: opozorila_rdeca vkljucuje baza_disk", [d.status, d.body && d.body.opozorila_rdeca]);
    assert((await klic(PORT, "/admin/api/opozorila", navaden)).status === 403, "navaden uporabnik: 403");
    assert((await klic(PORT, "/admin/api/opozorila")).status === 401, "brez zetona: 401");
  } finally { await b.ustavi(); }
  b = await zazeni(PORT, DB);
  try {
    const o = await klic(PORT, "/admin/api/opozorila", admin);
    assert(o.status === 200 && !o.body.items.some((x) => x.vrsta === "baza_disk"), "pod mejo: opozorila ni", o.body && o.body.items.map((x) => x.vrsta));
  } finally { await b.ustavi(); }
  // opozorila ne sprozijo nove poizvedbe ob vsakem ogledu panela: ena meritev za /healthz/baza in vse oglede
  pp = await posrednik();
  b = await zazeni(PORT, pp.url, { BAZA_DISK_MB: "1" });
  try {
    await klic(PORT, "/healthz/baza");
    for (let i = 0; i < 5; i++) await klic(PORT, "/admin/api/opozorila", admin);
    await klic(PORT, "/admin/api/danes", admin);
    assert(pp.st.meritev === 1, `healthz + 5x opozorila + danes = 1 poizvedba pg_database_size (${pp.st.meritev})`);
  } finally { await b.ustavi(); pp.zapri(); }

  // ---------------------------------------------------------------- B7
  console.log("\n# B7: enota baza_disk.js");
  const { ustvari } = require("../baza_disk");
  const napolni = (o = {}) => {
    const dnevnik = { connect: 0, release: [], q: [] };
    const lazniPool = { connect: async () => {
      dnevnik.connect++;
      if (o.connectCaka) await o.connectCaka;
      let sproscen = false;
      return { on() {}, release: (u) => { sproscen = true; dnevnik.release.push(!!u); }, query: async (sql) => {
        dnevnik.q.push(String(sql).slice(0, 40));
        if (/pg_database_size/.test(sql)) { if (o.poizvedbaCaka) await o.poizvedbaCaka; if (o.napaka) throw new Error("kvar"); return { rows: [{ bajti: o.bajtov || 524288000 }] }; }
        return { rows: [] };
      }, get sproscen() { return sproscen; } };
    } };
    return { lazniPool, dnevnik };
  };
  {
    const { lazniPool, dnevnik } = napolni({ bajtov: 524288000 });
    const m = ustvari({ pool: lazniPool, diskMb: 1024, opozoriloPct: 70, log: { error() {} } });
    const r = await Promise.all([m.izmeri(), m.izmeri(), m.izmeri()]);
    assert(r.every((x) => x === 49 || x === 50) && dnevnik.q.filter((s) => /pg_database_size/.test(s)).length === 1, `vzporedni klici = ena poizvedba, 500 MiB / 1024 MiB = ${r[0]} %`, r);
    assert(dnevnik.release.length === 1 && dnevnik.release[0] === false, "povezava gre nazaj v pool (cista)", dnevnik.release);
    await m.izmeri();
    assert(dnevnik.connect === 1, "drugi klic iz predpomnilnika");
  }
  {
    const { lazniPool, dnevnik } = napolni({ napaka: true });
    const m = ustvari({ pool: lazniPool, diskMb: 1024, opozoriloPct: 70, log: { error() {} }, veljaMs: 200 });
    assert((await m.izmeri()) === null, "napaka poizvedbe -> null");
    assert(dnevnik.release.length === 1 && dnevnik.release[0] === true, "povezava po napaki se unici", dnevnik.release);
    await m.izmeri();
    assert(dnevnik.connect === 1, "napaka se obdrzi kratek cas (brez nove poizvedbe v istem trenutku)");
  }
  {
    let sprosti; const caka = new Promise((r) => { sprosti = r; });
    const { lazniPool, dnevnik } = napolni({ poizvedbaCaka: caka });
    const m = ustvari({ pool: lazniPool, diskMb: 1024, opozoriloPct: 70, log: { error() {} }, rokMs: 150, veljaMs: 100 });
    const t0 = Date.now();
    assert((await m.izmeri()) === null && Date.now() - t0 < 1000, "obvisela poizvedba -> null v roku");
    assert(dnevnik.release.length === 1 && dnevnik.release[0] === true, "obvisela povezava se unici, ne vrne v pool", dnevnik.release);
    sprosti(); await spi(50);
    assert(dnevnik.release.length === 1, "zakasnel konec poizvedbe povezave ne sprosti drugic", dnevnik.release);
  }
  {
    let sprosti; const caka = new Promise((r) => { sprosti = r; });
    const { lazniPool, dnevnik } = napolni({ connectCaka: caka });
    const m = ustvari({ pool: lazniPool, diskMb: 1024, opozoriloPct: 70, log: { error() {} }, rokMs: 100, veljaMs: 100 });
    assert((await m.izmeri()) === null, "pool ne da povezave v roku -> null");
    sprosti(); await spi(50);
    assert(dnevnik.release.length === 1 && dnevnik.release[0] === true && dnevnik.q.length === 0, "povezava, ki pride prepozno, se takoj unici brez poizvedbe", [dnevnik.release, dnevnik.q]);
  }
  {
    const napake = [];
    const { lazniPool } = napolni({ bajtov: 900 * 1048576 });
    let ura = 1_000_000;
    const m = ustvari({ pool: lazniPool, diskMb: 1024, opozoriloPct: 70, log: { error: (s) => napake.push(s) }, veljaMs: 1, zdaj: () => ura });
    await m.izmeri(); await spi(5); await m.izmeri(); await spi(5);
    assert(napake.length === 1, `POZOR 1x v 6 h (${napake.length})`);
    ura += 10; await spi(5); await m.izmeri(); ura += 6 * 3600 * 1000 + 1; await spi(5); await m.izmeri();
    assert(napake.length === 2 && /POZOR/.test(napake[1]), `po 6 h spet (${napake.length})`);
  }

  console.log(`\n${ok} ok, ${fail} napak`);
  jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
