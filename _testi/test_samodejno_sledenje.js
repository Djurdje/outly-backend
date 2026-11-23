#!/usr/bin/env node
/**
 * Samodejno sledenje uradnemu profilu Outly (DECISIONS 2026-11-22; migracija 077).
 *  - NOV uporabnik (vrstica v `users` nastane ob prvem klicu z Supabasovim zetonom) sledi vsem klubom z is_official = TRUE,
 *    ki niso skriti in niso demo; samo ob nastanku (kdor odsledi, ga ne prijavi nic znova);
 *  - napaka pri sledenju ne podre prvega klica; brez uradnega kluba prvi klic dela;
 *  - migracija 077 doda sledenje obstojecim racunom, brez obvestil; ponovni zagon ne naredi nic;
 *  - PUSH (Martin 23. 11. 2026 »brez pusha«): samodejni sledilec (club_follows.samodejno = TRUE) dobi ob objavi dogodka uradnega kluba zvonec, push NE;
 *    kdor je sledil sam (PUT /clubs/:id/follow, tudi po odsledenju ali na ze obstojeci samodejni vrstici) dobi oboje; obstojeca izbrana vrstica ostane
 *    samodejno = FALSE tudi po migraciji. LAZNI APNs po vzorcu test_push.js (http2 + samopodpisan certifikat iz openssl, NODE_EXTRA_CA_CERTS).
 * Zagon: DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_samodejno_sledenje.js
 * Vzorec kot test_vabila.js: lokalni JWKS (6460), backend na 6461.
 */
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const http2 = require("http2");
const os = require("os");
const { execFileSync } = require("child_process");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6461, JWKS_PORT = 6460, APNS_PORT = 6462;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-1";
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
// --- lazni APNs (vzorec test_push.js) ---
const mapa = fs.mkdtempSync(path.join(os.tmpdir(), "outly-samodejno-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", path.join(mapa, "k.pem"), "-out", path.join(mapa, "c.pem"),
  "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { stdio: "ignore" });
const APNS_P8_B64 = Buffer.from(crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" })).toString("base64");
const zahteve = [];   // { zeton, json }
const apnsStreznik = http2.createSecureServer({ key: fs.readFileSync(path.join(mapa, "k.pem")), cert: fs.readFileSync(path.join(mapa, "c.pem")) });
apnsStreznik.on("session", (x) => x.on("error", () => {}));
apnsStreznik.on("stream", (stream, glave) => {
  stream.on("error", () => {});
  let telo = ""; stream.setEncoding("utf8"); stream.on("data", (d) => telo += d);
  stream.on("end", () => {
    let json = null; try { json = JSON.parse(telo); } catch { /* ostane null */ }
    zahteve.push({ zeton: String(glave[":path"]).split("/").pop(), json });
    try { stream.respond({ ":status": 200 }); stream.end(""); } catch { /* seja zaprta */ }
  });
});
const zet = (ime) => crypto.createHash("sha256").update("outly-samodejno-" + ime).digest("hex");
const cakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function pocakaj(pogoj, ms = 10000) { const konec = Date.now() + ms; while (Date.now() < konec) { if (pogoj()) return true; await cakaj(50); } return false; }
function uuid(n) { return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`; }
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path_, token, body, glave) {
  const r = await fetch(BASE + path_, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...(glave || {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, club_event_notifications, club_follows, club_invites, club_members, event_favorites, friendships, friend_requests, ticket_transfers, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => apnsStreznik.listen(APNS_PORT, r));
  const okolje = { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    APNS_KEY_ID: "TESTKEYID1", APNS_TEAM_ID: "TESTTEAM12", APNS_KEY_P8: APNS_P8_B64, APNS_HOST: `https://localhost:${APNS_PORT}`, NODE_EXTRA_CA_CERTS: path.join(mapa, "c.pem") };
  const srv = spawn("node", ["index.js"], { env: okolje, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
  const stSledenj = async (email) => (await pool.query("SELECT COUNT(*)::int AS n FROM club_follows f JOIN users u ON u.id=f.user_id WHERE u.email=$1", [email])).rows[0].n;
  const stPush = () => (log.match(/\[push\] club_event: \d+ naprav/g) || []).length;
  const samodejno = async (email, klub = 1) => { const q = await pool.query("SELECT f.samodejno FROM club_follows f JOIN users u ON u.id=f.user_id WHERE u.email=$1 AND f.club_id=$2", [email, klub]); return q.rows.length ? q.rows[0].samodejno : null; };
  const stSledilcev = async (id) => (await pool.query("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id=$1", [id])).rows[0].n;

  try {
    console.log("\n# Brez uradnega kluba prvi klic dela");
    const T = {};
    T.lastnik = zeton("lastnik@outly.si", uuid(1));
    let r = await api("GET", "/me", T.lastnik);
    assert(r.status === 200, "prvi klic brez uradnega kluba -> 200", r.body);
    assert((await stSledenj("lastnik@outly.si")) === 0, "brez uradnega kluba ni vrstic club_follows");

    // klubi: 1 uradni, 2 navaden, 3 uradni skrit, 4 uradni demo
    const idLastnik = (await pool.query("SELECT id FROM users WHERE email='lastnik@outly.si'")).rows[0].id;
    await pool.query("UPDATE users SET role='business' WHERE id=$1", [idLastnik]);
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, is_official, hidden, is_demo) VALUES
      ($1, 'Outly', 'Ljubljana', TRUE, FALSE, FALSE),
      ($1, 'Navaden klub', 'Ljubljana', FALSE, FALSE, FALSE),
      ($1, 'Skriti uradni', 'Maribor', TRUE, TRUE, FALSE),
      ($1, 'Demo uradni', 'Maribor', TRUE, FALSE, TRUE)`, [idLastnik]);

    console.log("\n# Novi racun sledi uradnemu profilu");
    T.ana = zeton("ana@outly.si", uuid(2));
    r = await api("GET", "/me", T.ana);
    assert(r.status === 200, "prvi klic nove uporabnice -> 200", r.body);
    r = await api("GET", "/clubs/1", T.ana);
    assert(r.status === 200 && r.body.is_following === true, "ana sledi uradnemu klubu (is_following)", r.body.is_following);
    assert((await stSledilcev(1)) === 1, "uradni klub ima 1 sledilca (ana)");
    r = await api("GET", "/clubs/2", T.ana);
    assert(r.body.is_following === false, "navadnemu klubu ne sledi", r.body.is_following);
    assert((await stSledilcev(3)) === 0 && (await stSledilcev(4)) === 0, "skritemu in demo uradnemu klubu ne sledi");
    r = await api("GET", "/me/clubs/following", T.ana);
    assert(r.status === 200 && r.body.ids.length === 1 && r.body.ids[0] === 1, "GET /me/clubs/following = samo uradni klub", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications")).rows[0].n === 0, "sledenje ne ustvari obvestil");

    console.log("\n# Odsledenje velja (ne ob prijavi, ne ob GET /me)");
    r = await api("DELETE", "/clubs/1/follow", T.ana);
    assert(r.status === 200 && r.body.following === false, "unfollow -> 200", r.body);
    await api("GET", "/me", T.ana);
    const T2 = zeton("ana@outly.si", uuid(2));   // nova prijava, isti racun
    r = await api("GET", "/me", T2);
    assert(r.status === 200, "ponovna prijava -> 200", r.body);
    r = await api("GET", "/clubs/1", T2);
    assert(r.body.is_following === false, "po unfollow in ponovni prijavi ne sledi vec", r.body.is_following);
    assert((await stSledilcev(1)) === 0, "uradni klub ima 0 sledilcev");


    console.log("\n# Stolpec samodejno: samodejni sledilec = TRUE, izbrani = FALSE");
    assert((await samodejno("ana@outly.si")) === null, "ana je odsledila: vrstice ni");
    T.sam1 = zeton("sam1@outly.si", uuid(10)); T.rocni = zeton("rocni@outly.si", uuid(11)); T.sam2 = zeton("sam2@outly.si", uuid(12)); T.sam3 = zeton("sam3@outly.si", uuid(13));
    for (const k of ["sam1", "rocni", "sam2", "sam3"]) {
      r = await api("GET", "/me", T[k]);
      assert(r.status === 200, `prvi klic ${k} -> 200`, r.body);
      assert((await samodejno(`${k}@outly.si`)) === true, `${k}: samodejno sledenje uradnemu klubu ima samodejno = TRUE`);
      r = await api("POST", "/me/devices", T[k], { token: zet(k), platform: "ios" });
      assert(r.status === 200, `${k}: naprava registrirana`, r.body);
    }
    r = await api("DELETE", "/clubs/1/follow", T.rocni);
    assert(r.status === 200 && (await samodejno("rocni@outly.si")) === null, "rocni odsledi: vrstice ni");
    r = await api("PUT", "/clubs/1/follow", T.rocni);
    assert(r.status === 200 && r.body.following === true && Object.keys(r.body).sort().join() === "followers_count,following", "rocni pritisne Follow: odgovor brez novih polj", r.body);
    assert((await samodejno("rocni@outly.si")) === false, "rocni: po Follow samodejno = FALSE");
    r = await api("PUT", "/clubs/1/follow", T.sam2);
    assert(r.status === 200 && r.body.following === true, "sam2 pritisne Follow na ze obstojeci samodejni vrstici -> 200", r.body);
    assert((await samodejno("sam2@outly.si")) === false, "sam2: PUT na samodejno vrstico jo spremeni v izbrano (FALSE)");
    r = await api("PUT", "/clubs/2/follow", T.sam1);
    assert(r.status === 200 && (await samodejno("sam1@outly.si", 2)) === false, "sam1 sledi navadnemu klubu: samodejno = FALSE");
    assert((await samodejno("sam3@outly.si")) === true, "sam3 ostane samodejni (TRUE)");

    console.log("\n# Objava dogodka uradnega kluba: zvonec za vse, push samo za izbrane");
    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '30 years')::date");
    zahteve.length = 0;
    let p0 = stPush();
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Uradni dogodek", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
    assert(r.status === 201, "uradni klub objavi dogodek", r.body);
    const E1 = r.body.id;
    assert(await pocakaj(() => stPush() >= p0 + 1), "push poslan (povzetek v dnevniku)");
    const zvonec = (await pool.query("SELECT u.email FROM club_event_notifications n JOIN users u ON u.id=n.user_id WHERE n.event_id=$1 ORDER BY u.email", [E1])).rows.map(x => x.email);
    assert(JSON.stringify(zvonec) === JSON.stringify(["rocni@outly.si", "sam1@outly.si", "sam2@outly.si", "sam3@outly.si"]), "zvonec dobijo VSI sledilci (tudi samodejni)", zvonec);
    assert(zahteve.length === 2 && JSON.stringify(zahteve.map(z => z.zeton).sort()) === JSON.stringify([zet("rocni"), zet("sam2")].sort()),
      "push SAMO rocni in sam2 (izbrana sledenja); sam1 in sam3 (samodejna) ga NE dobita", zahteve.map(z => z.zeton.slice(0, 6)));
    assert(zahteve.every(z => z.json && z.json.outly.type === "club_event" && z.json.outly.id === E1), "push je club_event za ta dogodek");

    console.log("\n# Navaden klub: ročni sledilec dobi push kot doslej");
    T.lastnik2 = zeton("lastnik2@outly.si", uuid(20));
    await api("GET", "/me", T.lastnik2);
    await pool.query("UPDATE users SET role='business', date_of_birth = (CURRENT_DATE - INTERVAL '30 years')::date WHERE email='lastnik2@outly.si'");
    await pool.query("UPDATE clubs SET owner_user_id = (SELECT id FROM users WHERE email='lastnik2@outly.si') WHERE id = 2");
    zahteve.length = 0; p0 = stPush();
    r = await api("POST", "/events", T.lastnik2, { clubId: 2, title: "Dogodek navadnega kluba", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
    assert(r.status === 201, "navadni klub objavi dogodek", r.body);
    assert(await pocakaj(() => stPush() >= p0 + 1), "push poslan");
    assert(zahteve.length === 1 && zahteve[0].zeton === zet("sam1"), "navadni klub: push na sam1 (izbral je sam)", zahteve.map(z => z.zeton.slice(0, 6)));
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications WHERE event_id=$1", [r.body.id])).rows[0].n === 1, "navadni klub: 1 vrstica v zvoncu");

    console.log("\n# Javni odgovori brez sprememb");
    r = await api("GET", "/clubs/1", T.rocni);
    assert(r.status === 200 && r.body.is_following === true && !("samodejno" in r.body), "GET /clubs/1: is_following brez novega polja", Object.keys(r.body));
    r = await api("GET", "/me/clubs/following", T.sam3);
    assert(r.status === 200 && Object.keys(r.body).join() === "ids,clubs" && r.body.ids.includes(1) && r.body.clubs.every(c => !("samodejno" in c)), "GET /me/clubs/following: oblika ids + clubs, brez novega polja", Object.keys(r.body));

    console.log("\n# Napaka pri sledenju ne podre prvega klica");
    await pool.query("ALTER TABLE club_follows RENAME TO club_follows_x");
    try {
      T.bor = zeton("bor@outly.si", uuid(3));
      r = await api("GET", "/me", T.bor);
      assert(r.status === 200 && r.body.email === "bor@outly.si", "prvi klic ob pokvarjenem sledenju -> 200", r);
      assert((await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE email='bor@outly.si'")).rows[0].n === 1, "uporabnik je nastal");
    } finally {
      await pool.query("ALTER TABLE club_follows_x RENAME TO club_follows");
    }
    assert(/\[sledenje\]|samodejno sledenje/i.test(log), "napaka je zabelezena (console.error)");
    r = await api("GET", "/me", T.bor);
    assert(r.status === 200, "naslednji klic dela", r.body);
    assert((await stSledenj("bor@outly.si")) === 0, "bor ni (vec) prijavljen samodejno: samo ob nastanku");

    console.log("\n# Migracija 077 za obstojece racune");
    const sql = fs.readFileSync(path.join(__dirname, "..", "db", "migracije", "077_sledenje_uradnemu_profilu.sql"), "utf8");
    await pool.query("INSERT INTO users (email, username, email_verified) VALUES ('stari1@outly.si','stari1',true), ('stari2@outly.si','stari2',true)");
    await pool.query("INSERT INTO club_follows (club_id, user_id) SELECT 1, id FROM users WHERE email='stari1@outly.si'");   // prava izbira pred 077 (samodejno privzeto FALSE)
    await pool.query("INSERT INTO club_event_notifications (user_id, event_id) SELECT 1, 1 WHERE FALSE");
    const obvestilPred = (await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications")).rows[0].n;
    const nUsers = (await pool.query("SELECT COUNT(*)::int AS n FROM users")).rows[0].n;
    await pool.query(sql);
    const po = (await pool.query("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id=1")).rows[0].n;
    assert(po === nUsers, `vsi racuni (${nUsers}) sledijo uradnemu klubu`, po);
    assert((await stSledilcev(2)) === 1 && (await stSledilcev(3)) === 0 && (await stSledilcev(4)) === 0, "migracija ne dodaja navadnemu (le sam1, ki je sledil sam), skritemu, demo");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications")).rows[0].n === obvestilPred, "migracija ne ustvari obvestil");
    const zdaj = (await pool.query("SELECT COUNT(*)::int AS n FROM club_follows")).rows[0].n;
    await pool.query(sql);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_follows")).rows[0].n === zdaj, "ponovni zagon migracije ne naredi nic");
    assert((await samodejno("stari1@outly.si")) === false, "migracija: obstojeca izbrana vrstica ostane samodejno = FALSE");
    assert((await samodejno("stari2@outly.si")) === true, "migracija: dodana vrstica ima samodejno = TRUE");
    const izbrani = (await pool.query("SELECT u.email FROM club_follows f JOIN users u ON u.id=f.user_id WHERE f.club_id=1 AND NOT f.samodejno ORDER BY u.email")).rows.map(x => x.email);
    assert(JSON.stringify(izbrani) === JSON.stringify(["rocni@outly.si", "sam2@outly.si", "stari1@outly.si"]), "migracija: samodejno = FALSE ostanejo samo izbrane vrstice", izbrani);

    console.log("\n# Migracija brez uradnega kluba uspe");
    await pool.query("UPDATE clubs SET is_official = FALSE");
    await pool.query("TRUNCATE club_follows");
    await pool.query(sql);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_follows")).rows[0].n === 0, "brez uradnega kluba migracija ne naredi nic");
  } finally {
    srv.kill();
    jwksServer.close();
    apnsStreznik.close();
    await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  if (fail) { console.log(log.split("\n").slice(-20).join("\n")); process.exit(1); }
})().catch((e) => { console.error(e); process.exit(1); });
