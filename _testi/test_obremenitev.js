#!/usr/bin/env node
/**
 * Obremenitveni test nakupa (issue #89): 300 razlicnih uporabnikov HKRATI kupi vstopnico za dogodek s kapaciteto 100,
 * medtem ko vratarji skenirajo vstopnice drugega dogodka. Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_obremenitev.js
 *
 * Vzorec kot test_vabila.js: lokalni JWKS (3995), backend na portu 3140 z QR_SECRET=test.
 * Nakupna pot: POST /events/:id/orders v testnem nacinu (brez Stripe, naročilo je takoj 'paid').
 * Omejevalnik "nakup" (20/uro na IP, index.js omeji()) steje po req.ip; ker je "trust proxy" 1, vzame req.ip iz
 * glave X-Forwarded-For - vsak navidezni uporabnik ima zato svoj naslov (kot v produkciji, kjer so kupci na razlicnih IP).
 * Posledica: test NE pokriva primera "vsi za istim NAT-om" (tam je meja 20 nakupov/uro na naslov).
 *
 * Preverja (invarianta I2 in "skeniranje ne sme pasti", docs/ARCHITECTURE.md):
 *   1. 300 prvih klicev GET /me hkrati (ustvarjanje uporabnikov): vsi 200, nobenega 5xx.
 *   2. 300 hkratnih nakupov (kolicina 1), kapaciteta 100: tocno 100 x 201, ostali 409, nobenega 5xx / 429;
 *      v bazi tocno 100 vstopnic in narocil, sold_count == capacity, noben kupec dvakrat, nobena zaloga negativna.
 *   3. Med nakupi 3 vratarji vzporedno skenirajo (POST /business/tickets/scan): vsi sken 200, p95 < 500 ms (meja je
 *      sproscena za pocasnejse GitHub runnerje; stara koda ~580-780 ms). 3b: ista navala + 1000 bralcev GET /events hkrati
 *      (p95 skena < 1000 ms, brez 5xx).
 *   4. 300 hkratnih nakupov z mesanimi kolicinami (1-4) za dogodek s kapaciteto 100: sold_count == vsota uspesnih,
 *      <= capacity, nobenega 5xx.
 *   5. Po koncu obremenitve backend takoj odgovarja: p95 20 zaporednih GET /events in 20 skenov < 500 ms.
 * Vrsta, prekinitve, 503 in sprostitev dovoljenja: _testi/test_nakup_vrsta.js.
 */
const os = require("os"), path = require("path");
const dc = require("diagnostics_channel"), { monitorEventLoopDelay } = require("perf_hooks");
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3140, JWKS_PORT = 3995;
const BASE = `http://127.0.0.1:${PORT}`;
const KUPCEV = 300, KAPACITETA = 100;
const SKEN_MEJA_MS = 500, BRALCEV = 1000, SKEN_KUPCEV = 40;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-obremenitev";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
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
function uuid(n) { return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`; }
// Vsak navidezni uporabnik ima svoj IP (glej opombo v glavi).
function ipUporabnika(i) { return `10.7.${(i >> 8) & 255}.${(i & 255) + 1}`; }
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path, token, body, ip) {
  const t0 = performance.now();
  try {
    const r = await fetch(BASE + path, {
      method,
      headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...(ip ? { "x-forwarded-for": ip } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30000),
    });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j, ms: performance.now() - t0 };
  } catch (e) {
    return { status: e.name === "TimeoutError" ? "timeout" : "omrezje", body: String(e.message), ms: performance.now() - t0 };
  }
}
function percentil(sortirano, p) { return sortirano.length ? sortirano[Math.min(sortirano.length - 1, Math.floor(sortirano.length * p))] : NaN; }
function steviloPoStatusu(rezultati) { const s = {}; for (const r of rezultati) s[r.status] = (s[r.status] || 0) + 1; return s; }
const je5xx = r => typeof r.status !== "number" || r.status >= 500;

// Diagnostika jedra (issue #139): ob p95 skena ~3,5 s (ujema se s ponovnim SYN po 1 s + 2 s) mora izpis pokazati, ali je jedro
// zavrglo ali ponovno poslalo povezavo. Samo Linux (/proc); drugje (macOS) se izpis tiho preskoci.
const JEDRO_STEVCI = {
  netstat: ["ListenOverflows", "ListenDrops", "TCPReqQFullDrop", "TCPReqQFullDoCookies", "SyncookiesSent", "TCPSynRetrans", "TCPTimeouts"],
  snmp: ["ActiveOpens", "PassiveOpens", "AttemptFails", "EstabResets", "RetransSegs"],
};
function preberiProc(pot) {
  const v = require("fs").readFileSync(pot, "utf8").trim().split("\n"), izh = {};
  for (let i = 0; i + 1 < v.length; i += 2) {
    const [ime, ...kljuci] = v[i].split(/\s+/), [ime2, ...vrednosti] = v[i + 1].split(/\s+/);   // "TcpExt:" vrstica imen, nato vrstica vrednosti
    if (ime !== ime2) continue;
    kljuci.forEach((k, j) => { izh[ime + k] = Number(vrednosti[j]); });   // ime ze vsebuje ":"
  }
  return izh;
}
function jedroStevci() {
  try {
    const ns = preberiProc("/proc/net/netstat"), sn = preberiProc("/proc/net/snmp"), s = {};
    for (const k of JEDRO_STEVCI.netstat) s[k] = ns["TcpExt:" + k];
    for (const k of JEDRO_STEVCI.snmp) s[k] = sn["Tcp:" + k];
    return s;
  } catch { return null; }
}
function jedroSysctl() {
  const fs = require("fs"), s = {};
  for (const [k, pot] of [["somaxconn", "/proc/sys/net/core/somaxconn"], ["tcp_max_syn_backlog", "/proc/sys/net/ipv4/tcp_max_syn_backlog"],
    ["tcp_syncookies", "/proc/sys/net/ipv4/tcp_syncookies"], ["tcp_synack_retries", "/proc/sys/net/ipv4/tcp_synack_retries"], ["ip_local_port_range", "/proc/sys/net/ipv4/ip_local_port_range"]]) {
    try { s[k] = fs.readFileSync(pot, "utf8").trim().replace(/\s+/g, "-"); } catch { /* ni Linux */ }
  }
  return s;
}
// Sled zahtevkov skena (odjemalec): undici sporoca ustvaritev zahtevka, pisanje glav (vkljucno z lokalnim vratom vticnice) in
// prihod odgovora. Skupaj s sledom strezniskega predala (_testi/sled_streznika.js) razdeli cas: cakanje odjemalca / sprejem
// povezave na strezniku / obdelava / vrnitev. Brez pomena za trditve testa.
const SLED_STREZNIK = path.join(os.tmpdir(), `outly-sled-obremenitev-${process.pid}.jsonl`);
const sledSkenov = [], sledZahtevkov = new Map();
dc.subscribe("undici:request:create", ({ request }) => { if (request.path.includes("/scan")) sledZahtevkov.set(request, { create: Date.now() }); });
dc.subscribe("undici:client:sendHeaders", ({ request, socket }) => { const r = sledZahtevkov.get(request); if (r) { r.send = Date.now(); r.port = socket.localPort; } });
dc.subscribe("undici:request:headers", ({ request }) => { const r = sledZahtevkov.get(request); if (r) { r.headers = Date.now(); sledSkenov.push(r); sledZahtevkov.delete(request); } });
const zankaOdjemalca = monitorEventLoopDelay({ resolution: 10 }); zankaOdjemalca.enable();
const sledZanke = [];
const sledVrste = [];   // dolzina vrste sprejemanja (rx_queue vticnice LISTEN) na vratih backenda
function dolzinaVrsteSprejemanja() {
  try {
    const vrstice = require("fs").readFileSync("/proc/net/tcp", "utf8").split("\n");
    const hex = ":" + PORT.toString(16).toUpperCase().padStart(4, "0");
    for (const l of vrstice) { const c = l.trim().split(/\s+/); if (c[3] === "0A" && c[1] && c[1].endsWith(hex)) return parseInt(c[4].split(":")[1], 16); }
  } catch { /* ni Linux */ }
  return null;
}
const sledCasovnik = setInterval(() => {
  sledZanke.push({ t: Date.now(), max: Math.round(zankaOdjemalca.max / 1e6) }); zankaOdjemalca.reset();
  const v = dolzinaVrsteSprejemanja(); if (v !== null) sledVrste.push({ t: Date.now(), v });
}, 100);
sledCasovnik.unref();
function izpisiSledPocasnih(skeni, meja = 500) {
  let streznik = [];
  try { streznik = require("fs").readFileSync(SLED_STREZNIK, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)); } catch { /* predala ni */ }
  const pocasni = sledSkenov.filter(r => r.headers - r.create > meja);
  if (!pocasni.length) return;
  const maxV = (a, b, k, vir) => Math.max(0, ...vir.filter(x => x.t >= a && x.t <= b).map(x => x[k]));
  for (const r of pocasni.slice(0, 6)) {
    const req = streznik.find(x => x.k === "req" && x.port === r.port && x.t >= r.send - 5);
    const fin = req && streznik.find(x => x.k === "fin" && x.port === req.port && x.t >= req.t);
    console.log("  (pocasen sken: " + JSON.stringify({
      skupajMs: r.headers - r.create, odjemalecCakaMs: r.send - r.create, odPosiljanjaDoStreznikovegaZahtevkaMs: req ? req.t - r.send : null,
      novaPovezava: req ? req.n === 1 : null, odSprejemaPovezaveDoZahtevkaMs: req && req.connT ? req.t - req.connT : null,
      streznikObdelavaMs: fin ? fin.ms : null, odOdgovoraDoOdjemalcevihGlavMs: fin ? r.headers - fin.t : null,
      zankaStreznikaMaxMs: maxV(r.create, r.headers, "max", streznik.filter(x => x.k === "loop")), zankaOdjemalcaMaxMs: maxV(r.create, r.headers, "max", sledZanke),
      vrstaSprejemanjaMax: maxV(r.create, r.headers, "v", sledVrste) }) + ")");
  }
}
function razlikaStevcev(pred, po) {
  if (!pred || !po) return null;
  const d = {};
  for (const k of Object.keys(po)) if (Number.isFinite(po[k]) && Number.isFinite(pred[k])) d[k] = po[k] - pred[k];
  return d;
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await pool.query("TRUNCATE omejitve");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  // Javni predpomnilnik (#114) je tu IZKLOPLJEN (JAVNI_PREDPOMNILNIK_MS=0), ker test meri izolacijo skena in nakupov od BAZE:
  // s predpomnilnikom 1000 bralcev istega kljuca postane ena poizvedba + 1000 x 100 kB odgovora, torej meri zasedenost
  // izvajalne zanke Node (p95 skena ~1,07 s v 2 od 3 zagonov, nestabilno), ne poolov. Predpomnilnik sam pokriva
  // test_javni_predpomnilnik.js; nakupi in sken predpomnilnika sploh ne uporabljajo (nakup ga celo izprazni).
  const srv = spawn("node", ["index.js"], { env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --require ${path.join(__dirname, "sled_streznika.js")}`.trim(), SLED_STREZNIK, PORT: String(PORT), JAVNI_PREDPOMNILNIK_MS: "0", SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  const lastnik = zeton("lastnik@outly.si", uuid(1));
  const vratarji = [2, 3, 4].map(n => ({ token: zeton(`vratar${n}@outly.si`, uuid(n)), email: `vratar${n}@outly.si` }));
  // Kupci vstopnic za skeniranje (40 x 10 = 400 vstopnic dogodka B) in 300 kupcev za obremenitev.
  const skenKupci = Array.from({ length: SKEN_KUPCEV }, (_, i) => zeton(`skenkupec${i}@outly.si`, uuid(500 + i)));
  const kupci = Array.from({ length: KUPCEV }, (_, i) => zeton(`kupec${i}@outly.si`, uuid(1000 + i)));

  console.log("# Priprava: lastnik, vratarji, klub, dogodki");
  let r = await api("GET", "/me", lastnik);
  assert(r.status === 200, "GET /me lastnik", r.body);
  for (const v of vratarji) { r = await api("GET", "/me", v.token); assert(r.status === 200, `GET /me ${v.email}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Obremenitev Club', 'Ljubljana')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) SELECT 1, id, 'doorman' FROM users WHERE email LIKE 'vratar%@outly.si'");
  const nov = async (title, capacity, cena) => {
    const x = await api("POST", "/events", lastnik, { clubId: 1, title, startAt: cezDan, ticketPriceCents: cena, capacity, minAge: 0 });
    assert(x.status === 201, `dogodek "${title}" ustvarjen (kapaciteta ${capacity})`, x.body);
    return x.body.id;
  };
  const dogodekA = await nov("Obremenitev A (100)", KAPACITETA, 1500);
  const dogodekB = await nov("Obremenitev B (sken)", 450, 1000);
  const dogodekC = await nov("Obremenitev C (mesane kolicine)", KAPACITETA, 800);
  const dogodekD = await nov("Obremenitev D (navala + bralci)", KAPACITETA, 900);

  // Se 150 javnih dogodkov z daljsim opisom: GET /events vrne ~100 kB, bralci ob navali niso brezplacni.
  await pool.query(`INSERT INTO events (club_id, title, description, start_at, status, ticket_price_cents, capacity)
                    SELECT 1, 'Polnilo ' || g, repeat('Opis dogodka. ', 25), NOW() + (g || ' hours')::interval, 'published', 1000, 100
                    FROM generate_series(1, 150) g`);

  console.log("\n# 1. 300 prvih klicev GET /me hkrati (ustvarjanje uporabnikov)");
  let t0 = performance.now();
  const me = await Promise.all(kupci.map((t, i) => api("GET", "/me", t, null, ipUporabnika(i))));
  console.log(`  (${Math.round(performance.now() - t0)} ms, statusi ${JSON.stringify(steviloPoStatusu(me))})`);
  assert(me.every(x => x.status === 200), "vseh 300 GET /me -> 200", steviloPoStatusu(me));
  const stU = await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE email LIKE 'kupec%@outly.si'");
  assert(stU.rows[0].n === KUPCEV, "v bazi 300 kupcev, brez podvojenih", stU.rows[0]);
  for (const t of skenKupci) { const x = await api("GET", "/me", t); if (x.status !== 200) assert(false, "GET /me skenkupec", x.body); }

  // Vstopnice dogodka B za skeniranje (nakupi po 10, vsak z lastnim IP).
  const kodeSken = [];
  for (let i = 0; i < skenKupci.length; i++) {
    const x = await api("POST", `/events/${dogodekB}/orders`, skenKupci[i], { quantity: 10 }, ipUporabnika(5000 + i));
    if (x.status !== 201) { assert(false, "priprava vstopnic za sken", x.body); continue; }
    for (const v of x.body.tickets) kodeSken.push(v.qr);
  }
  assert(kodeSken.length === 400, "pripravljenih 400 vstopnic dogodka B za sken", kodeSken.length);

  // Rezerva za sken po obremenitvi (skenerji med navalo lahko porabijo vse ostale kode).
  const kodePoNavali = kodeSken.splice(0, 20);

  // Izhodisce: sken brez obremenitve.
  const izhodisce = [];
  for (let i = 0; i < 10; i++) { const x = await api("POST", "/business/tickets/scan", vratarji[0].token, { qr: kodeSken.pop() }); izhodisce.push(x); }
  assert(izhodisce.every(x => x.status === 200 && x.body.result === "ok"), "sken brez obremenitve -> 200 ok (10x)", izhodisce.map(x => x.status));
  const izhSort = izhodisce.map(x => x.ms).sort((a, b) => a - b);
  console.log(`  (sken brez obremenitve: p50 ${percentil(izhSort, 0.5).toFixed(1)} ms, max ${izhSort[izhSort.length - 1].toFixed(1)} ms)`);

  let skenovSkupaj = 10;   // izhodiscnih 10 + vsi med navalami
  // Ena navala: 300 hkratnih nakupov za dogodek + (neobvezno) bralci GET /events hkrati + 3 vratarji skenirajo.
  async function navala(dogodek, bralcev) {
    let nakupiKonec = false;
    const tNavale = performance.now();   // zacetek navale; skeni si zapomnijo zamik (diagnostika #139)
    const skeni = [];   // { status, result, ms, zacetek }
    async function skener(v) {
      while (!nakupiKonec && kodeSken.length) {
        const zacetek = performance.now() - tNavale;
        const x = await api("POST", "/business/tickets/scan", v.token, { qr: kodeSken.pop() });
        skeni.push({ status: x.status, result: x.body && x.body.result, ms: x.ms, zacetek });
        await new Promise(rs => setTimeout(rs, bralcev ? 15 : 5));
      }
    }
    const skenerji = vratarji.map(skener);
    await new Promise(rs => setTimeout(rs, 100));   // skenerji tecejo, ko se sprozi navala
    const t = performance.now();
    const bralci = Array.from({ length: bralcev }, () => api("GET", "/events?upcoming=true"));   // hkrati z nakupi
    const nakupi = await Promise.all(kupci.map((tok, i) => api("POST", `/events/${dogodek}/orders`, tok, { quantity: 1 }, ipUporabnika(i))));
    const trajanje = performance.now() - t;
    nakupiKonec = true;
    await Promise.all(skenerji);
    const bralciRez = await Promise.all(bralci);
    skenovSkupaj += skeni.length;
    return { nakupi, trajanje, skeni, bralciRez };
  }
  function preveriSkene(oznaka, skeni, meja = SKEN_MEJA_MS) {
    const ms = skeni.map(x => x.ms).sort((a, b) => a - b);
    console.log(`  (sken ${oznaka}: ${skeni.length} skenov, p50 ${percentil(ms, 0.5).toFixed(1)} ms, p95 ${percentil(ms, 0.95).toFixed(1)} ms, max ${ms.length ? ms[ms.length - 1].toFixed(1) : "-"} ms)`);
    assert(skeni.length >= 10, `${oznaka}: med nakupi je steklo vsaj 10 skenov`, skeni.length);
    assert(skeni.every(x => x.status === 200 && x.result === "ok"), `${oznaka}: vsak sken -> 200 ok`, skeni.filter(x => !(x.status === 200 && x.result === "ok")).slice(0, 3));
    assert(percentil(ms, 0.95) < meja, `${oznaka}: p95 skena < ${meja} ms`, percentil(ms, 0.95));
    // Najpocasnejsi sken: eno-nitni Node je ob 1000 hkratnih velikih odgovorih (JSON) zaseden, zato max ni stabilna meja; ujame le obvisel sken.
    assert(ms.length && ms[ms.length - 1] < 8000, `${oznaka}: noben sken ne visi (max < 8 s)`, ms[ms.length - 1]);
  }

  console.log("\n# 2+3. 300 hkratnih nakupov (kapaciteta 100) + sken med obremenitvijo");
  const { nakupi, trajanje: trajanjeNakupov, skeni } = await navala(dogodekA, 0);

  const stNakupov = steviloPoStatusu(nakupi);
  const nakupMs = nakupi.map(x => x.ms).sort((a, b) => a - b);
  console.log(`  (nakupi: ${Math.round(trajanjeNakupov)} ms skupaj, statusi ${JSON.stringify(stNakupov)}, p50 ${percentil(nakupMs, 0.5).toFixed(0)} ms, p95 ${percentil(nakupMs, 0.95).toFixed(0)} ms, max ${nakupMs[nakupMs.length - 1].toFixed(0)} ms)`);
  assert((stNakupov[201] || 0) === KAPACITETA, "tocno 100 nakupov uspe (201)", stNakupov);
  assert((stNakupov[409] || 0) === KUPCEV - KAPACITETA, "ostalih 200 dobi 409 (ni dovolj vstopnic)", stNakupov);
  assert(!nakupi.some(je5xx), "nobenega 5xx / timeouta med nakupi", nakupi.filter(je5xx).slice(0, 3));
  assert(!nakupi.some(x => x.status === 429), "nobenega 429 (vsak kupec svoj IP)", stNakupov);
  assert(nakupi.filter(x => x.status === 409).every(x => /tickets left|Not enough/i.test(String(x.body))), "409 nosi sporocilo o zalogi", nakupi.find(x => x.status === 409 && !/tickets left|Not enough/i.test(String(x.body))));

  const ev = await pool.query("SELECT capacity, sold_count FROM events WHERE id=$1", [dogodekA]);
  assert(ev.rows[0].sold_count === KAPACITETA && ev.rows[0].capacity === KAPACITETA, "sold_count == capacity == 100", ev.rows[0]);
  const vst = await pool.query("SELECT COUNT(*)::int AS n, COUNT(DISTINCT serial)::int AS razl FROM tickets WHERE event_id=$1", [dogodekA]);
  assert(vst.rows[0].n === KAPACITETA && vst.rows[0].razl === KAPACITETA, "v bazi tocno 100 vstopnic (vsaka svoj serial)", vst.rows[0]);
  const nar = await pool.query("SELECT COUNT(*)::int AS n, COUNT(DISTINCT user_id)::int AS kupcev, COALESCE(SUM(quantity),0)::int AS kolicina FROM orders WHERE event_id=$1 AND status='paid'", [dogodekA]);
  assert(nar.rows[0].n === KAPACITETA && nar.rows[0].kupcev === KAPACITETA && nar.rows[0].kolicina === KAPACITETA, "100 placanih narocil, 100 razlicnih kupcev", nar.rows[0]);
  const uspesnaNarocila = new Set(nakupi.filter(x => x.status === 201).map(x => x.body.order.id));
  assert(uspesnaNarocila.size === KAPACITETA, "100 uspesnih odgovorov = 100 razlicnih narocil", uspesnaNarocila.size);
  const neg = await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE sold_count < 0 OR (capacity IS NOT NULL AND sold_count > capacity)");
  assert(neg.rows[0].n === 0, "noben dogodek nima negativne ali presezene zaloge", neg.rows[0]);

  preveriSkene("navala nakupov", skeni);

  console.log("\n# 3b. Navala 300 nakupov + 1000 bralcev GET /events hkrati + sken (dogodek D)");
  const tZacetek3b = Date.now();
  const jedroPred = jedroStevci();
  console.log(`  (jedro pred 3b: sysctl ${JSON.stringify(jedroSysctl())}, stevci ${JSON.stringify(jedroPred)})`);
  const d = await navala(dogodekD, BRALCEV);
  const jedroRazlika = razlikaStevcev(jedroPred, jedroStevci());
  await new Promise(rs => setTimeout(rs, 300));   // predal strezniku zapisuje vsake 250 ms
  izpisiSledPocasnih(d.skeni);
  console.log(`  (vrsta sprejemanja na vratih ${PORT} med 3b: najvec ${Math.max(0, ...sledVrste.filter(x => x.t >= tZacetek3b).map(x => x.v))} povezav; zanka odjemalca najvec ${Math.max(0, ...sledZanke.filter(x => x.t >= tZacetek3b).map(x => x.max))} ms)`);
  if (jedroRazlika && Object.keys(jedroRazlika).length) {
    console.log(`  (jedro med 3b, razlika stevcev: ${JSON.stringify(jedroRazlika)})`);
    const pocasni = d.skeni.filter(x => x.ms > 500).map(x => `+${Math.round(x.zacetek)} ms: ${Math.round(x.ms)} ms`);
    if (pocasni.length) console.log(`  (skeni pocasnejsi od 500 ms [zacetek od navale: trajanje]: ${pocasni.join(", ")})`);
    const zavrzeno = (jedroRazlika.ListenOverflows || 0) + (jedroRazlika.ListenDrops || 0) + (jedroRazlika.TCPReqQFullDrop || 0);
    if (zavrzeno > 0) console.log(`  !! jedro je med 3b zavrglo povezave (ListenOverflows+ListenDrops+TCPReqQFullDrop = ${zavrzeno}): vrsta sprejemanja/SYN je prepolna, ne zakasnitev aplikacije`);
    else if ((jedroRazlika.TCPSynRetrans || 0) > 0) console.log(`  !! ponovno poslanih SYN: ${jedroRazlika.TCPSynRetrans} (brez zavrzenih v ListenOverflows/Drops - SYN vrsta ali SYN piskoti)`);
    else console.log("  (jedro ni zavrglo nobene povezave in ni bilo ponovnih SYN: zakasnitev, ce je je, ni zavrnitev jedra)");
  }
  const stD = steviloPoStatusu(d.nakupi);
  const bralciMs = d.bralciRez.map(x => x.ms).sort((a, b) => a - b);
  console.log(`  (nakupi ${Math.round(d.trajanje)} ms, statusi ${JSON.stringify(stD)}; bralci: ${BRALCEV} x GET /events, statusi ${JSON.stringify(steviloPoStatusu(d.bralciRez))}, p50 ${percentil(bralciMs, 0.5).toFixed(0)} ms, p95 ${percentil(bralciMs, 0.95).toFixed(0)} ms)`);
  assert(!d.bralciRez.some(je5xx), "nobenega 5xx / timeouta pri 1000 bralcih", d.bralciRez.filter(je5xx).slice(0, 3));
  assert(!d.nakupi.some(je5xx) && (stD[201] || 0) === KAPACITETA && (stD[409] || 0) === KUPCEV - KAPACITETA, "tudi ob 1000 bralcih: 100 x 201, 200 x 409, brez 5xx", stD);
  const evD = await pool.query("SELECT sold_count FROM events WHERE id=$1", [dogodekD]);
  assert(evD.rows[0].sold_count === KAPACITETA, "dogodek D: sold_count == 100", evD.rows[0]);
  // Meja 1000 ms: ob 1000 hkratnih velikih odgovorih je eno-nitni Node procesorsko zaseden (na enem jedru p95 ~400 ms) - tu lovimo
  // vrsto za povezavo (sekunde), ne CPU. Natancnejso mejo (500 ms) drzi navala brez bralcev zgoraj.
  preveriSkene("navala + 1000 bralcev", d.skeni, 1000);
  const porabljene = await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE event_id=$1 AND status='used'", [dogodekB]);
  assert(porabljene.rows[0].n === skenovSkupaj, "v bazi je tocno toliko porabljenih vstopnic, kolikor je bilo skenov", { baza: porabljene.rows[0].n, skenov: skenovSkupaj });

  console.log("\n# 4. 300 hkratnih nakupov z mesanimi kolicinami (1-4), kapaciteta 100");
  t0 = performance.now();
  const kolicine = kupci.map((_, i) => 1 + (i * 7) % 4);   // deterministicno 1..4
  const mesani = await Promise.all(kupci.map((t, i) => api("POST", `/events/${dogodekC}/orders`, t, { quantity: kolicine[i] }, ipUporabnika(i))));
  const stMesani = steviloPoStatusu(mesani);
  console.log(`  (${Math.round(performance.now() - t0)} ms, statusi ${JSON.stringify(stMesani)})`);
  assert(!mesani.some(je5xx), "nobenega 5xx / timeouta", mesani.filter(je5xx).slice(0, 3));
  assert(mesani.every(x => x.status === 201 || x.status === 409), "samo 201 ali 409", stMesani);
  const vsotaUspesnih = mesani.reduce((s, x, i) => s + (x.status === 201 ? kolicine[i] : 0), 0);
  const evC = await pool.query("SELECT capacity, sold_count FROM events WHERE id=$1", [dogodekC]);
  const vstC = await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE event_id=$1", [dogodekC]);
  assert(evC.rows[0].sold_count === vsotaUspesnih, "sold_count == vsota kolicin uspesnih nakupov", { sold: evC.rows[0].sold_count, vsota: vsotaUspesnih });
  assert(evC.rows[0].sold_count <= KAPACITETA && evC.rows[0].sold_count >= KAPACITETA - 3, "prodanih najvec 100 in zaloga skoraj porabljena (ostanek < 4)", evC.rows[0]);
  assert(vstC.rows[0].n === evC.rows[0].sold_count, "stevilo vstopnic == sold_count", { vstopnic: vstC.rows[0].n, sold: evC.rows[0].sold_count });
  const neg2 = await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE sold_count < 0 OR (capacity IS NOT NULL AND sold_count > capacity)");
  assert(neg2.rows[0].n === 0, "noben dogodek nima negativne ali presezene zaloge", neg2.rows[0]);

  console.log("\n# 5. Po obremenitvi backend takoj odgovarja");
  const poBranje = [], poSken = [];
  for (let i = 0; i < 20; i++) poBranje.push(await api("GET", "/events"));
  for (const koda of kodePoNavali) poSken.push(await api("POST", "/business/tickets/scan", vratarji[1].token, { qr: koda }));
  const pbMs = poBranje.map(x => x.ms).sort((a, b) => a - b), psMs = poSken.map(x => x.ms).sort((a, b) => a - b);
  console.log(`  (po navali: GET /events p95 ${percentil(pbMs, 0.95).toFixed(0)} ms, sken p95 ${percentil(psMs, 0.95).toFixed(0)} ms)`);
  assert(poBranje.every(x => x.status === 200) && percentil(pbMs, 0.95) < SKEN_MEJA_MS, `GET /events po obremenitvi: 20 x 200, p95 < ${SKEN_MEJA_MS} ms`, percentil(pbMs, 0.95));
  assert(poSken.every(x => x.status === 200 && x.body.result === "ok") && percentil(psMs, 0.95) < SKEN_MEJA_MS, `sken po obremenitvi: 20 x ok, p95 < ${SKEN_MEJA_MS} ms`, percentil(psMs, 0.95));

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.slice(0, 20).join("\n"));
  srv.kill(); try { require("fs").unlinkSync(SLED_STREZNIK); } catch { /* ni datoteke */ }
  jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
