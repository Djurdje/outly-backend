#!/usr/bin/env node
/**
 * Test: POTISNA OBVESTILA APNs + REGISTRACIJA NAPRAV (migracija 040, invarianta I29, issue #183).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami; potreben je `openssl`):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_push.js
 * Vzorec kot test_strezba.js / test_vabila.js: lokalni JWKS (3957), backend kot otrok proces (3207; drugi brez APNS_* na 3208), TRUNCATE na zacetku.
 * LAZNI APNs: http2.createSecureServer na localhostu s samopodpisanim certifikatom, ustvarjenim v testu (openssl); backend mu zaupa prek
 * NODE_EXTRA_CA_CERTS (nastavitev procesa, ne kode: produkcija ostane nespremenjena), APNS_HOST kaze nanj. Testni kljuc je P-256 (APNS_KEY_P8 = base64 .p8).
 * Pokriva: (g) POST/DELETE /me/devices; (a) JWT (kid, iss, iat, podpis ieee-p1363), glave, payload; (b) 410 / BadDeviceToken oznacita invalid_at, naslednji dogodek
 * takemu zetonu ne poslje, ponovna registracija ga vrne; (c) strezba VIP mize: lastnik + manager + natakar, NE vratar/kupec/tuj natakar, brez osebnih podatkov;
 * (d) prenos vstopnice, objava dogodka sledilcu, vabilo na guest listo; (e) brez APNS_* vse dela enako, push se ne poslje; (f) APNs, ki ne odgovori / vrne 500 /
 * prekine povezavo, sken ne upocasni in ne podre.
 */
const crypto = require("crypto");
const http = require("http");
const http2 = require("http2");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, execFileSync } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3207, PORT_BREZ = 3208, JWKS_PORT = 3957, APNS_PORT = 3959;
const BASE = `http://127.0.0.1:${PORT}`, BASE_BREZ = `http://127.0.0.1:${PORT_BREZ}`;
const APNS_TIMEOUT_MS = 2500;

// --- identiteta (lokalni JWKS kot v ostalih testih) ---
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-push";
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
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
let ipStevec = 0;
const novIp = () => `10.41.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`;
async function apiNa(baza, method, p, token, body, glave) {
  const r = await fetch(baza + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": novIp(), ...(token ? { authorization: "Bearer " + token } : {}), ...(glave || {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, besedilo: t };
}
const api = (...a) => apiNa(BASE, ...a);
const cakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function pocakaj(pogoj, ms = 8000) {
  const konec = Date.now() + ms;
  while (Date.now() < konec) { if (await pogoj()) return true; await cakaj(50); }
  return false;
}
// 64-mestni heksadecimalni zeton naprave z razpoznavnim zacetkom.
const ZETON_N = {};
function zet(ime) {
  if (!ZETON_N[ime]) ZETON_N[ime] = crypto.createHash("sha256").update("outly-push-test-" + ime).digest("hex");
  return ZETON_N[ime];
}

// --- laznni APNs ---
const mapa = fs.mkdtempSync(path.join(os.tmpdir(), "outly-push-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", path.join(mapa, "k.pem"), "-out", path.join(mapa, "c.pem"),
  "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { stdio: "ignore" });
const apnsKljuc = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const APNS_P8_PEM = apnsKljuc.privateKey.export({ type: "pkcs8", format: "pem" });
const APNS_P8_B64 = Buffer.from(APNS_P8_PEM).toString("base64");
const zahteve = [];                       // sprejeti zahtevki { zeton, glave, telo }
const vedenje = new Map();                // zeton -> "ok" | { status, reason } | "hang" | "reset"
let rezim = "ok";                         // "ok" | "hang" | "500" | "reset": prepise vedenje za vse zetone
const viseci = new Set();
const apnsStreznik = http2.createSecureServer({ key: fs.readFileSync(path.join(mapa, "k.pem")), cert: fs.readFileSync(path.join(mapa, "c.pem")) });
apnsStreznik.on("session", (s) => s.on("error", () => {}));
apnsStreznik.on("stream", (stream, glave) => {
  const seja = stream.session;
  stream.on("error", () => {});
  let telo = "";
  stream.setEncoding("utf8");
  stream.on("data", (d) => telo += d);
  stream.on("end", () => {
    const zeton = String(glave[":path"]).split("/").pop();
    let json = null; try { json = JSON.parse(telo); } catch { /* ostane null */ }
    zahteve.push({ zeton, glave, telo, json });
    const v = rezim !== "ok" ? rezim : (vedenje.get(zeton) || "ok");
    if (v === "hang") { viseci.add(stream); return; }
    if (v === "reset") { seja.destroy(); return; }
    const odgovor = (status, razlog) => {
      stream.respond({ ":status": status, "content-type": "application/json" });
      stream.end(razlog ? JSON.stringify({ reason: razlog }) : "");
    };
    if (v === "ok") return odgovor(200);
    if (v === "500") return odgovor(500, "InternalServerError");
    return odgovor(v.status, v.reason);
  });
});

const urejeniZahtevki = (zeton) => zahteve.filter(z => z.zeton === zeton);

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, device_tokens, club_event_notifications, club_follows, guest_list_members, guest_lists, table_service, table_holds, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users, friendships RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => apnsStreznik.listen(APNS_PORT, r));
  const okoljeOsnova = { ...process.env, SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" };
  for (const k of Object.keys(okoljeOsnova)) if (k.startsWith("APNS_")) delete okoljeOsnova[k];
  const zazeni = (port, dodatno) => {
    const s = spawn("node", ["index.js"], { env: { ...okoljeOsnova, PORT: String(port), ...dodatno }, stdio: ["ignore", "pipe", "pipe"] });
    const o = { proc: s, log: "" }; s.stdout.on("data", d => o.log += d); s.stderr.on("data", d => o.log += d);
    return o;
  };
  const srv = zazeni(PORT, {
    APNS_KEY_ID: "TESTKEYID1", APNS_TEAM_ID: "TESTTEAM12", APNS_KEY_P8: APNS_P8_B64,
    APNS_HOST: `https://localhost:${APNS_PORT}`, APNS_TIMEOUT_MS: String(APNS_TIMEOUT_MS),
    NODE_EXTRA_CA_CERTS: path.join(mapa, "c.pem"),
  });
  const brez = zazeni(PORT_BREZ, { APNS_HOST: `https://localhost:${APNS_PORT}`, NODE_EXTRA_CA_CERTS: path.join(mapa, "c.pem") });   // brez kljucev: push izklopljen
  for (const b of [BASE, BASE_BREZ]) for (let i = 0; i < 100; i++) { try { await fetch(b + "/"); break; } catch { await cakaj(100); } }

  try {
    const imena = ["lastnik", "manager", "doorman", "natakar", "tujnatakar", "tujlastnik", "kupec", "kupec2", "prejemnik", "sledilec", "sledilec2", "nesledilec", "admin", "gostitelj", "povabljenec"];
    const T = {}, U = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','tujlastnik@outly.si')");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '30 years')::date WHERE email NOT LIKE 'admin%'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Pure Club', 'Ljubljana')", [U.lastnik]);
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Tuj Klub', 'Maribor')", [U.tujlastnik]);
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, $1, 'manager'), (1, $2, 'doorman'), (1, $3, 'bartender'), (2, $4, 'bartender')", [U.manager, U.doorman, U.natakar, U.tujnatakar]);
    await pool.query("INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int))", [U.gostitelj, U.povabljenec]);
    let r;

    // ------------------------------------------------------------------------------------------------------------------
    console.log("\n# (g) POST/DELETE /me/devices");
    const Z = { mojZeton: zet("moj") };
    r = await api("POST", "/me/devices", null, { token: Z.mojZeton, platform: "ios" });
    assert(r.status === 401, "POST brez zetona -> 401", r.status);
    r = await api("DELETE", `/me/devices/${Z.mojZeton}`, null);
    assert(r.status === 401, "DELETE brez zetona -> 401", r.status);
    for (const [ime, telo] of [["brez telesa", undefined], ["brez token", { platform: "ios" }], ["token ni niz", { token: 12345 }], ["token prekratek (63)", { token: "a".repeat(63) }],
      ["token predolg (201)", { token: "a".repeat(201) }], ["token ni heksadecimalen", { token: "g".repeat(64) }], ["token s presledkom", { token: "a".repeat(63) + " " }],
      ["token s potjo", { token: "../".repeat(30) }], ["platform android", { token: Z.mojZeton, platform: "android" }], ["platform ni niz", { token: Z.mojZeton, platform: 1 }]]) {
      r = await api("POST", "/me/devices", T.natakar, telo);
      assert(r.status === 400 && r.body && typeof r.body.error === "string" && typeof r.body.message === "string", `neveljaven vhod (${ime}) -> 400 { error, message }`, [r.status, r.body]);
    }
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens")).rows[0].n === 0, "po neveljavnih vhodih v bazi ni zetonov");
    r = await api("POST", "/me/devices", T.natakar, { token: Z.mojZeton, platform: "ios" });
    assert(r.status === 200 && r.body.ok === true, "veljaven zeton -> 200 { ok: true }", r.body);
    let vrst = (await pool.query("SELECT * FROM device_tokens")).rows;
    assert(vrst.length === 1 && vrst[0].user_id === U.natakar && vrst[0].token === Z.mojZeton && vrst[0].platform === "ios" && vrst[0].invalid_at === null, "v bazi: 1 vrstica, uporabnik, platform ios, invalid_at NULL", vrst);
    r = await api("POST", "/me/devices", T.natakar, { token: Z.mojZeton });
    assert(r.status === 200, "ponovitev (platform privzeto ios) je idempotentna -> 200", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens")).rows[0].n === 1, "se vedno 1 vrstica");
    r = await api("POST", "/me/devices", T.natakar, { token: Z.mojZeton.toUpperCase() });
    assert(r.status === 200 && (await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens")).rows[0].n === 1, "isti zeton z VELIKIMI crkami je isti zeton (zapis v malih crkah)");
    // Tuj zeton: drug uporabnik ga ne izbrise.
    r = await api("DELETE", `/me/devices/${Z.mojZeton}`, T.kupec);
    assert(r.status === 204, "tuj zeton: DELETE -> 204 (ne razkrije)", r.status);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens WHERE token=$1 AND user_id=$2", [Z.mojZeton, U.natakar])).rows[0].n === 1, "tuj DELETE zetona NI izbrisal");
    // Isti zeton na drugem racunu (odjava, prijava na isti napravi) se prepise; invalid_at gre na NULL.
    await pool.query("UPDATE device_tokens SET invalid_at = NOW() - INTERVAL '1 hour', last_seen_at = NOW() - INTERVAL '1 day' WHERE token = $1", [Z.mojZeton]);
    r = await api("POST", "/me/devices", T.kupec, { token: Z.mojZeton });
    vrst = (await pool.query("SELECT * FROM device_tokens WHERE token=$1", [Z.mojZeton])).rows;
    assert(r.status === 200 && vrst.length === 1 && vrst[0].user_id === U.kupec && vrst[0].invalid_at === null && Date.now() - vrst[0].last_seen_at.getTime() < 60000,
      "isti zeton na drugem racunu: prepis user_id, invalid_at NULL, last_seen_at osvezen", vrst);
    r = await api("DELETE", `/me/devices/${Z.mojZeton}`, T.kupec);
    assert(r.status === 204 && (await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens")).rows[0].n === 0, "lasten zeton: DELETE -> 204 in vrstica je izbrisana");
    r = await api("DELETE", `/me/devices/${Z.mojZeton}`, T.kupec);
    assert(r.status === 204, "neobstojec zeton: DELETE -> 204");
    r = await api("DELETE", "/me/devices/xyz", T.kupec);
    assert(r.status === 400, "DELETE z neveljavnim zetonom -> 400", [r.status, r.body]);
    // Omejevalnik (60/h/IP).
    const fiksen = { "x-forwarded-for": "10.99.99.99" };
    let zadnji = null, prva429 = 0;
    for (let i = 1; i <= 62; i++) { zadnji = await api("DELETE", `/me/devices/${zet("omejitev")}`, T.kupec, undefined, fiksen); if (zadnji.status === 429 && !prva429) prva429 = i; }
    assert(prva429 === 61 && zadnji.status === 429, "omejevalnik: 61. zahtevek z istega IP -> 429", [prva429, zadnji.status]);
    await pool.query("TRUNCATE omejitve");
    // Izbris racuna pobrise naprave (kaskada): tecken v ločenem sklopu spodaj (uporabnik brez klubov).

    // ------------------------------------------------------------------------------------------------------------------
    console.log("\n# Priprava: tloris, dogodek, kupci VIP miz, naprave");
    const PLAN = { width: 24, height: 16, elements: [{ type: "stage", x: 8, y: 0, w: 8, h: 3, label: "" }] };
    const mize = Array.from({ length: 8 }, (_, i) => ({ label: `T${i + 1}`, x: 1 + i * 2, y: 5, w: 1, h: 1, shape: "round", seats: 4, price_cents: 10000 }));
    r = await api("PUT", "/business/vip", T.lastnik, { plan: PLAN, tables: mize, packages: [{ name: "Jameson 0,7 l", description: "4x Red Bull" }] });
    assert(r.status === 200 && r.body.tables.length === 8, "tloris (8 miz, 1 paket)", r.body);
    const M = r.body.tables.map(t => t.id), P1 = r.body.packages[0].id;
    const E1 = (await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, status, ticket_price_cents, capacity, vip_enabled)
       VALUES (1, 'Push noc', 'https://example.com/p.jpg', NOW() + INTERVAL '2 hours', 'published', 1500, 100, FALSE) RETURNING id`)).rows[0].id;
    r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true });
    assert(r.status === 200, "VIP vklopljen", r.body);
    const kupi = async (tok, i) => {
      const x = await api("POST", `/events/${E1}/tables/${M[i]}/orders`, tok, { package_id: P1 });
      assert(x.status === 201, `nakup mize T${i + 1}`, x.body);
      return x.body.order.id;
    };
    const O = [];
    O[0] = await kupi(T.kupec, 0); O[1] = await kupi(T.kupec2, 1); O[2] = await kupi(T.kupec, 2); O[3] = await kupi(T.kupec2, 3);
    O[4] = await kupi(T.kupec, 4); O[5] = await kupi(T.kupec2, 5); O[6] = await kupi(T.kupec, 6); O[7] = await kupi(T.kupec2, 7);
    const vsi = [...(await api("GET", "/me/tickets", T.kupec)).body, ...(await api("GET", "/me/tickets", T.kupec2)).body];
    const qrZa = (orderId) => vsi.filter(t => t.order_id === orderId && t.is_vip);
    assert(O.every(o => qrZa(o).length === 4 && qrZa(o).every(t => t.qr)), "vsako VIP narocilo ima 4 vstopnice s QR", O.map(o => qrZa(o).length));
    // Zeton -> uporabnik in vedenje lazne APNs
    const NAPRAVE = [
      ["lastnik", zet("L1"), "ok"], ["manager", zet("M1"), "ok"], ["manager", zet("M2-410"), { status: 410, reason: "Unregistered" }],
      ["natakar", zet("N1"), "ok"], ["natakar", zet("N2-bad"), { status: 400, reason: "BadDeviceToken" }], ["natakar", zet("N3-topic"), { status: 400, reason: "DeviceTokenNotForTopic" }],
      ["natakar", zet("N4-badtopic"), { status: 400, reason: "BadTopic" }], ["natakar", zet("N5-500"), { status: 500, reason: "InternalServerError" }],
      ["doorman", zet("D1"), "ok"], ["kupec", zet("K1"), "ok"], ["kupec2", zet("K2"), "ok"], ["tujnatakar", zet("TN1"), "ok"], ["tujlastnik", zet("TL1"), "ok"],
      ["prejemnik", zet("P1"), "ok"], ["sledilec", zet("S1"), "ok"], ["nesledilec", zet("X1"), "ok"], ["gostitelj", zet("G1"), "ok"], ["povabljenec", zet("V1"), "ok"],
    ];
    for (const [uporabnik, z, v] of NAPRAVE) {
      vedenje.set(z, v);
      const x = await api("POST", "/me/devices", T[uporabnik], { token: z, platform: "ios" });
      assert(x.status === 200, `naprava ${uporabnik}`, x.body);
    }
    const imeZetona = new Map(NAPRAVE.map(([, z]) => [z, z]));
    const zetoniPo = (zahteve2) => zahteve2.map(z => z.zeton).sort();
    const pricakovani = (...ime) => ime.map(zet).sort();

    // ------------------------------------------------------------------------------------------------------------------
    console.log("\n# (c) Strezba VIP mize: lastnik + manager + natakar, NE vratar / kupec / tuj natakar");
    zahteve.length = 0;
    const skeniraj = async (tok, qr) => { const t0 = Date.now(); const x = await api("POST", "/business/tickets/scan", tok, { qr }); x.ms = Date.now() - t0; return x; };
    r = await skeniraj(T.doorman, qrZa(O[0])[0].qr);
    assert(r.status === 200 && r.body.result === "ok" && r.body.table_service_created === true, "vratar skenira VIP vstopnico T1 -> ok, table_service_created", r.body);
    assert(!("table_service_id" in r.body) && !("table_service_id" in r.body.ticket), "odgovor skena ostane enak: brez novega polja table_service_id");
    const S1 = (await pool.query("SELECT id FROM table_service WHERE order_id=$1", [O[0]])).rows[0].id;
    const prvi = ["L1", "M1", "M2-410", "N1", "N2-bad", "N3-topic", "N4-badtopic", "N5-500"];
    assert(await pocakaj(() => zahteve.length >= prvi.length), "APNs je prejel push", zahteve.length);
    await cakaj(500);
    assert(JSON.stringify(zetoniPo(zahteve)) === JSON.stringify(pricakovani(...prvi)), "prejemniki: lastnik (1) + manager (2) + natakar (5 naprav); NIC vratar, kupca, tujega natakarja/lastnika", zahteve.map(z => z.zeton.slice(0, 6)));
    const z0 = zahteve.find(z => z.zeton === zet("L1"));
    assert(z0.json.outly.type === "table_service" && z0.json.outly.id === S1 && typeof z0.json.outly.id === "number", "payload: outly.type table_service, outly.id = id strezbe (stevilo)", z0.json);
    assert(z0.json.aps.alert["loc-key"] === "VIP table %@ is ready to be served" && JSON.stringify(z0.json.aps.alert["loc-args"]) === JSON.stringify(["T1"]) && z0.json.aps.alert["title-loc-key"] === "VIP table" && z0.json.aps.sound === "default",
      "payload: loc-key (angleski niz), loc-args [oznaka mize], title-loc-key, sound", z0.json.aps);
    assert(!/kupec|@|outly\.si|Jameson|Red Bull/i.test(z0.telo.replace(/%@/g, "")), "payload NE vsebuje imena, uporabniskega imena, e-naslova kupca (niti paketa) - I27", z0.telo);
    assert(Object.keys(z0.json).sort().join() === "aps,outly" && Object.keys(z0.json.outly).sort().join() === "id,type", "payload ima samo aps + outly { type, id }");
    // (a) glave in JWT
    const g0 = z0.glave;
    assert(g0[":method"] === "POST" && g0[":path"] === `/3/device/${zet("L1")}` && g0["apns-topic"] === "si.outly.app" && g0["apns-push-type"] === "alert" && g0["apns-priority"] === "10",
      "(a) glave: POST /3/device/<zeton>, apns-topic si.outly.app, apns-push-type alert, apns-priority 10", g0);
    assert(/^\d+$/.test(g0["apns-expiration"]) && Number(g0["apns-expiration"]) > Date.now() / 1000 && Number(g0["apns-expiration"]) <= Date.now() / 1000 + 3700, "(a) strezba ima apns-expiration (~1 h)", g0["apns-expiration"]);
    const auth = String(g0.authorization);
    assert(auth.startsWith("bearer "), "(a) authorization: bearer <jwt>", auth.slice(0, 12));
    const [jh, jp, js] = auth.slice(7).split(".");
    const glavaJwt = JSON.parse(Buffer.from(jh, "base64url")), telesoJwt = JSON.parse(Buffer.from(jp, "base64url"));
    assert(glavaJwt.alg === "ES256" && glavaJwt.kid === "TESTKEYID1", "(a) JWT glava: alg ES256, kid = APNS_KEY_ID", glavaJwt);
    assert(telesoJwt.iss === "TESTTEAM12" && Math.abs(telesoJwt.iat - Date.now() / 1000) < 120, "(a) JWT telo: iss = APNS_TEAM_ID, iat = zdaj", telesoJwt);
    const podpis = Buffer.from(js, "base64url");
    assert(podpis.length === 64, "(a) podpis je 64 bajtov (ieee-p1363), NE DER", podpis.length);
    assert(crypto.verify("sha256", Buffer.from(jh + "." + jp), { key: apnsKljuc.publicKey, dsaEncoding: "ieee-p1363" }, podpis), "(a) podpis JWT se preveri z JAVNIM ključem APNs ključa");
    assert(zahteve.every(z => z.glave.authorization === auth), "(a) JWT je predpomnjen: vsi zahtevki isti zeton");
    // druga vstopnica istega narocila: NIC
    zahteve.length = 0;
    r = await skeniraj(T.doorman, qrZa(O[0])[1].qr);
    assert(r.status === 200 && r.body.table_service_created === false, "druga vstopnica istega narocila: ok, table_service_created = false");
    // (b) 410 in 400: invalid_at; naslednji push jim ne gre
    assert(await pocakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens WHERE invalid_at IS NOT NULL")).rows[0].n >= 3, 4000), "(b) po 1. pushu so neveljavni oznaceni v bazi");
    const neveljavni = (await pool.query("SELECT token FROM device_tokens WHERE invalid_at IS NOT NULL ORDER BY token")).rows.map(x => x.token);
    assert(JSON.stringify(neveljavni) === JSON.stringify(pricakovani("M2-410", "N2-bad", "N3-topic")), "(b) neveljavni: 410 Unregistered, 400 BadDeviceToken, 400 DeviceTokenNotForTopic; NE BadTopic in NE 500", neveljavni.map(t => t.slice(0, 6)));
    assert(zahteve.length === 0, "druga vstopnica istega narocila ni sprozila pusha", zahteve.length);
    r = await skeniraj(T.doorman, qrZa(O[1])[0].qr);
    assert(r.status === 200 && r.body.table_service_created === true, "sken T2 (drugo narocilo) -> nova strezba");
    const cakanih = ["L1", "M1", "N1", "N4-badtopic", "N5-500"];
    assert(await pocakaj(() => zahteve.length >= cakanih.length), "(b) 2. push prispe", zahteve.length);
    await cakaj(500);
    assert(JSON.stringify(zetoniPo(zahteve)) === JSON.stringify(pricakovani(...cakanih)), "(b) 2. push NE gre na M2-410, N2-bad, N3-topic; gre na veljavne in na zacasno neuspele", zahteve.map(z => z.zeton.slice(0, 6)));
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens WHERE invalid_at IS NOT NULL")).rows[0].n === 3, "(b) BadTopic in 500 zetona NE oznacita kot neveljavnega");
    // ponovna registracija vrne M2-410
    r = await api("POST", "/me/devices", T.manager, { token: zet("M2-410") });
    assert(r.status === 200 && (await pool.query("SELECT invalid_at FROM device_tokens WHERE token=$1", [zet("M2-410")])).rows[0].invalid_at === null, "(b) ponovna registracija postavi invalid_at na NULL");
    zahteve.length = 0;
    r = await skeniraj(T.doorman, qrZa(O[2])[0].qr);
    assert(r.body.table_service_created === true, "sken T3 -> nova strezba");
    assert(await pocakaj(() => zahteve.length >= 6), "(b) push za T3 prispe (L1, M1, M2-410, N1, N4, N5)", zahteve.length);
    await cakaj(500);
    assert(urejeniZahtevki(zet("M2-410")).length === 1, "(b) po ponovni registraciji M2-410 spet dobi push (in ga 410 zopet oznaci)");
    // sken brez povezave
    zahteve.length = 0;
    let n = 0;
    const sken = (qr, minut) => ({ client_scan_id: `cs-push-${++n}`, qr, scanned_at: new Date(Date.now() - minut * 60000).toISOString(), device_id: "telefon-push-1" });
    r = await api("POST", "/business/tickets/scan-batch", T.doorman, { scans: [sken(qrZa(O[3])[0].qr, 5), sken(qrZa(O[3])[1].qr, 5), sken(qrZa(O[4])[0].qr, 4)] });
    assert(r.status === 200 && r.body.results.every(x => x.result === "ok") && r.body.results[0].table_service_created === true && r.body.results[1].table_service_created === false, "scan-batch: 2 novi strezbi (T4, T5), druga vstopnica T4 ne", r.body.results);
    assert(!JSON.stringify(r.body).includes("table_service_id"), "odgovor scan-batch brez table_service_id");
    assert(await pocakaj(() => zahteve.length >= 10, 6000), "scan-batch: push za vsako novo strezbo (T4, T5)", zahteve.length);
    await cakaj(400);
    const poOznaki = (oznaka) => zahteve.filter(z => z.json.aps.alert["loc-args"][0] === oznaka);
    assert(poOznaki("T4").length >= 5 && poOznaki("T5").length >= 5 && zahteve.every(z => ["T4", "T5"].includes(z.json.aps.alert["loc-args"][0])), "scan-batch: obvestila za T4 in T5, ne za drugo vstopnico T4", zahteve.map(z => z.json.aps.alert["loc-args"][0]));
    // Star sken brez povezave (2 h): strezba nastane, push ne (zastarelo)
    await pool.query("UPDATE tickets SET created_at = NOW() - INTERVAL '5 hours' WHERE order_id = $1", [O[5]]);
    zahteve.length = 0;
    r = await api("POST", "/business/tickets/scan-batch", T.doorman, { scans: [sken(qrZa(O[5])[0].qr, 120)] });
    assert(r.status === 200 && r.body.results[0].result === "ok" && r.body.results[0].table_service_created === true, "star sken brez povezave (2 h): strezba nastane");
    await cakaj(800);
    assert(zahteve.length === 0, "zastarela strezba (sken star 2 h) pusha NE sprozi", zahteve.length);
    // Seznam ostane: strezba je v bazi
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM table_service")).rows[0].n === 6, "v bazi je 6 strezb (T1-T6)");
    // vloga iz baze ob posiljanju: odstranjen natakar ne dobi vec
    await pool.query("DELETE FROM club_members WHERE user_id = $1", [U.natakar]);
    zahteve.length = 0;
    r = await skeniraj(T.doorman, qrZa(O[6])[0].qr);
    assert(r.body.table_service_created === true, "sken T7 -> nova strezba");
    assert(await pocakaj(() => zahteve.length >= 2), "push po odstranitvi natakarja prispe");
    await cakaj(400);
    assert(zahteve.every(z => [zet("L1"), zet("M1"), zet("M2-410")].includes(z.zeton)), "odstranjen natakar (clanstvo v bazi) push NE dobi vec (vloga ob posiljanju, I5)", zahteve.map(z => z.zeton.slice(0, 6)));
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, $1, 'bartender')", [U.natakar]);

    // ------------------------------------------------------------------------------------------------------------------
    console.log("\n# (d) Prenos vstopnice, objava dogodka, vabilo na guest listo");
    // d1: prenos vstopnice
    r = await api("POST", `/events/${E1}/orders`, T.kupec, { quantity: 2 });
    assert(r.status === 201, "kupec kupi 2 navadni vstopnici", r.body);
    const nav = (await api("GET", "/me/tickets", T.kupec)).body.filter(t => !t.is_vip && t.event_id === E1);
    zahteve.length = 0;
    r = await api("POST", `/tickets/${nav[0].id}/transfer`, T.kupec, { email: "prejemnik@outly.si" });
    assert(r.status === 200 && r.body.result === "ok", "prenos vstopnice prejemniku z racunom -> 200", r.body);
    assert(await pocakaj(() => zahteve.length >= 1), "prenos: push prispe");
    await cakaj(400);
    assert(zahteve.length === 1 && zahteve[0].zeton === zet("P1"), "prenos: push SAMO na napravo prejemnika (ne posiljatelj, ne tretji)", zahteve.map(z => z.zeton.slice(0, 6)));
    const pr = zahteve[0].json;
    assert(pr.outly.type === "ticket_received" && pr.outly.id === nav[0].id && pr.aps.alert["loc-key"] === "%@ sent you a ticket" && JSON.stringify(pr.aps.alert["loc-args"]) === JSON.stringify(["kupec"]) && pr.aps.alert["title-loc-key"] === "New ticket",
      "prenos: type ticket_received, id = vstopnica, loc-key, loc-args [uporabnisko ime posiljatelja]", pr);
    assert(!zahteve[0].glave["apns-expiration"], "prenos: brez apns-expiration");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM ticket_transfers WHERE to_user_id=$1 AND seen_at IS NULL", [U.prejemnik])).rows[0].n === 1, "prenos: vrstica v zvoncu (ticket_transfers, seen_at NULL) je se vedno tu");
    // d2: objava dogodka sledilcem
    r = await api("PUT", "/clubs/1/follow", T.sledilec);
    assert(r.status === 200 || r.status === 204 || r.status === 201, "sledilec sledi klubu", [r.status, r.body]);
    await api("PUT", "/clubs/1/follow", T.sledilec2);
    zahteve.length = 0;
    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Nov Dogodek", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
    assert(r.status === 201, "klub objavi dogodek (published)", r.body);
    const E2 = r.body.id;
    assert(await pocakaj(() => zahteve.length >= 1), "objava: push prispe");
    await cakaj(400);
    assert(zahteve.length === 1 && zahteve[0].zeton === zet("S1"), "objava: push SAMO na napravo sledilca (sledilec2 brez naprave, nesledilec ne)", zahteve.map(z => z.zeton.slice(0, 6)));
    const ob = zahteve[0].json;
    assert(ob.outly.type === "club_event" && ob.outly.id === E2 && ob.aps.alert["loc-key"] === "%@ posted a new event: %@" && JSON.stringify(ob.aps.alert["loc-args"]) === JSON.stringify(["Pure Club", "Nov Dogodek"]) && ob.aps.alert["title-loc-key"] === "New event",
      "objava: type club_event, id = dogodek, loc-args [klub, naslov]", ob);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications WHERE event_id=$1", [E2])).rows[0].n === 2, "objava: 2 vrstici v zvoncu (oba sledilca)");
    // osnutek -> objavljen (PATCH) = push; ponovna objava (draft -> published) ne podvoji
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Osnutek", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0, status: "draft" });
    assert(r.status === 201 && r.body.status === "draft", "osnutek", r.body);
    const E3 = r.body.id;
    zahteve.length = 0;
    await cakaj(500);
    assert(zahteve.length === 0, "osnutek pusha ne sprozi", zahteve.length);
    r = await api("PATCH", `/events/${E3}`, T.lastnik, { status: "published" });
    assert(r.status === 200 && r.body.status === "published", "osnutek -> objavljen (PATCH)", r.body);
    assert(await pocakaj(() => zahteve.length >= 1), "PATCH objava: push prispe");
    await cakaj(300);
    assert(zahteve.length === 1 && zahteve[0].json.outly.id === E3 && zahteve[0].json.aps.alert["loc-args"][1] === "Osnutek", "PATCH objava: 1 push z naslovom dogodka", zahteve.map(z => z.json));
    zahteve.length = 0;
    await api("PATCH", `/events/${E3}`, T.lastnik, { status: "draft" });
    await api("PATCH", `/events/${E3}`, T.lastnik, { status: "published" });
    await cakaj(800);
    assert(zahteve.length === 0, "ponovna objava (draft -> published): v zvoncu ni nove vrstice, zato tudi pusha ne", zahteve.length);
    // skriti klub
    await pool.query("UPDATE clubs SET hidden = TRUE WHERE id = 1");
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Skrit", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
    await cakaj(800);
    assert(zahteve.length === 0, "skriti klub: objava pusha ne sprozi", zahteve.length);
    await pool.query("UPDATE clubs SET hidden = FALSE WHERE id = 1");
    // d3: guest lista
    r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: E1, user_id: U.gostitelj, spots: 3 });
    assert(r.status === 201, "admin ustvari guest listo", r.body);
    const GL = r.body.guest_list.id;
    zahteve.length = 0;
    r = await api("POST", `/me/guest-lists/${GL}/invites`, T.gostitelj, { user_ids: [U.povabljenec] });
    assert(r.status === 201, "gostitelj povabi prijatelja", r.body);
    const clan = (await pool.query("SELECT id, ticket_id FROM guest_list_members WHERE guest_list_id=$1 AND user_id=$2", [GL, U.povabljenec])).rows[0];
    assert(await pocakaj(() => zahteve.length >= 1), "vabilo: push prispe");
    await cakaj(400);
    assert(zahteve.length === 1 && zahteve[0].zeton === zet("V1"), "vabilo: push SAMO na napravo povabljenca (ne gostitelj)", zahteve.map(z => z.zeton.slice(0, 6)));
    const gv = zahteve[0].json;
    assert(gv.outly.type === "guest_list_invite" && gv.outly.id === Number(clan.ticket_id) && gv.aps.alert["loc-key"] === "%@ added you to their guest list" && JSON.stringify(gv.aps.alert["loc-args"]) === JSON.stringify(["gostitelj"]) && gv.aps.alert["title-loc-key"] === "Guest list",
      "vabilo: type guest_list_invite, id = id VSTOPNICE povabljenca, loc-args [uporabnisko ime gostitelja]", gv);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM guest_list_members WHERE user_id=$1 AND seen_at IS NULL AND removed_at IS NULL", [U.povabljenec])).rows[0].n === 1, "vabilo: vrstica v zvoncu (guest_list_members, seen_at NULL) je se vedno tu");

    // ------------------------------------------------------------------------------------------------------------------
    console.log("\n# (f) APNs ne odgovori / 500 / prekine povezavo: sken ostane hiter in ne pade");
    // Za 3 preizkuse (hang, 500, reset) potrebujemo nova VIP narocila: nakupi na novem dogodku.
    const E4 = (await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, status, ticket_price_cents, capacity, vip_enabled)
       VALUES (1, 'Push noc 2', 'https://example.com/p.jpg', NOW() + INTERVAL '2 hours', 'published', 1500, 100, FALSE) RETURNING id`)).rows[0].id;
    await api("PUT", `/business/events/${E4}/vip`, T.lastnik, { enabled: true });
    const kupi4 = async (tok, i) => (await api("POST", `/events/${E4}/tables/${M[i]}/orders`, tok, { package_id: P1 })).body.order.id;
    const O4 = [await kupi4(T.kupec, 0), await kupi4(T.kupec2, 1), await kupi4(T.kupec, 2), await kupi4(T.kupec2, 3)];
    const vsi4 = [...(await api("GET", "/me/tickets", T.kupec)).body, ...(await api("GET", "/me/tickets", T.kupec2)).body].filter(t => t.event_id === E4 && t.is_vip);
    const qr4 = (i) => vsi4.filter(t => t.order_id === O4[i])[0].qr;
    await pool.query("UPDATE device_tokens SET invalid_at = NULL");   // vsi zetoni spet veljavni
    // f1: APNs sprejme zahtevek, a ne odgovori
    rezim = "hang"; zahteve.length = 0;
    r = await skeniraj(T.doorman, qr4(0));
    assert(r.status === 200 && r.body.result === "ok" && r.body.table_service_created === true, "(f) APNs visi: sken -> 200 ok, strezba nastane", r.body);
    assert(r.ms < APNS_TIMEOUT_MS - 800, `(f) sken NE caka na push (${r.ms} ms < ${APNS_TIMEOUT_MS - 800} ms; rok APNs je ${APNS_TIMEOUT_MS} ms)`, r.ms);
    assert(await pocakaj(() => zahteve.length >= 1), "(f) push je bil poskusen (zahtevek je prispel na lazni APNs)");
    const t1 = Date.now();
    const m = await api("GET", "/me", T.lastnik);
    r = await skeniraj(T.doorman, qr4(1));
    assert(m.status === 200 && Date.now() - t1 < 1500, "(f) med visecim APNs GET /me in drugi sken odgovorita takoj", Date.now() - t1);
    assert(r.status === 200 && r.body.table_service_created === true && r.ms < APNS_TIMEOUT_MS - 800, `(f) drugi sken med visecim APNs: 200 (${r.ms} ms)`, r.ms);
    await cakaj(APNS_TIMEOUT_MS + 1500);
    assert(zahteve.length > 0 && (await api("GET", "/me", T.lastnik)).status === 200, "(f) po izteku roka APNs je backend zdrav");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens WHERE invalid_at IS NOT NULL")).rows[0].n === 0, "(f) timeout zetonov NE oznaci kot neveljavnih");
    for (const s of viseci) { try { s.close(); } catch { /* ze zaprt */ } }
    viseci.clear();
    // f2: APNs vrne 500
    rezim = "500"; zahteve.length = 0;
    r = await skeniraj(T.doorman, qr4(2));
    assert(r.status === 200 && r.body.table_service_created === true && r.ms < 1500, `(f) APNs 500: sken 200 (${r.ms} ms)`, r.body);
    assert(await pocakaj(() => zahteve.length >= 1), "(f) push poskusen, APNs je odgovoril 500");
    await cakaj(500);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens WHERE invalid_at IS NOT NULL")).rows[0].n === 0, "(f) 500 zetonov NE oznaci kot neveljavnih");
    // f3: APNs prekine povezavo
    rezim = "reset"; zahteve.length = 0;
    r = await skeniraj(T.doorman, qr4(3));
    assert(r.status === 200 && r.body.table_service_created === true && r.ms < 1500, `(f) APNs prekine povezavo: sken 200 (${r.ms} ms)`, r.body);
    assert(await pocakaj(() => zahteve.length >= 1), "(f) push poskusen, povezava prekinjena");
    await cakaj(1500);
    assert((await api("GET", "/me", T.lastnik)).status === 200, "(f) backend po prekinjeni povezavi z APNs zdrav");
    // f4: okrevanje - nova seja
    rezim = "ok"; zahteve.length = 0;
    const zadnja = qrZa(O[7])[0].qr;
    r = await skeniraj(T.doorman, zadnja);
    assert(r.status === 200 && r.body.table_service_created === true, "(f) APNs spet dela: sken T8");
    assert(await pocakaj(() => zahteve.length >= 5), "(f) po okrevanju push spet gre (nova HTTP/2 seja)", zahteve.length);

    // ------------------------------------------------------------------------------------------------------------------
    console.log("\n# (e) Brez APNS_* spremenljivk: vse poti delajo enako, push se ne poslje");
    assert(/\[push\] izklopljen/.test(brez.log) && !/\[push\] vklopljen/.test(brez.log), "dnevnik brez kljucev: ena vrstica »[push] izklopljen«", brez.log.slice(0, 300));
    assert(/\[push\] vklopljen/.test(srv.log), "dnevnik s kljuci: »[push] vklopljen«");
    const E5 = (await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, status, ticket_price_cents, capacity, vip_enabled)
       VALUES (1, 'Brez pusha', 'https://example.com/p.jpg', NOW() + INTERVAL '2 hours', 'published', 1500, 100, FALSE) RETURNING id`)).rows[0].id;
    const apiB = (...a) => apiNa(BASE_BREZ, ...a);
    await apiB("PUT", `/business/events/${E5}/vip`, T.lastnik, { enabled: true });
    const nakup5 = await apiB("POST", `/events/${E5}/tables/${M[0]}/orders`, T.kupec, { package_id: P1 });
    assert(nakup5.status === 201, "(e) nakup mize brez pusha", nakup5.body);
    const vsi5 = (await apiB("GET", "/me/tickets", T.kupec)).body.filter(t => t.event_id === E5);
    const obNav = await apiB("POST", `/events/${E5}/orders`, T.kupec, { quantity: 1 });
    assert(obNav.status === 201, "(e) nakup navadne vstopnice");
    zahteve.length = 0;
    r = await apiB("POST", "/business/tickets/scan", T.doorman, { qr: vsi5.find(t => t.is_vip).qr });
    assert(r.status === 200 && r.body.result === "ok" && r.body.table_service_created === true, "(e) sken VIP vstopnice brez pusha: 200, strezba nastane", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM table_service WHERE order_id=$1", [nakup5.body.order.id])).rows[0].n === 1, "(e) strezba (seznam natakarja) je v bazi");
    const nav5 = (await apiB("GET", "/me/tickets", T.kupec)).body.find(t => t.event_id === E5 && !t.is_vip);
    r = await apiB("POST", `/tickets/${nav5.id}/transfer`, T.kupec, { email: "prejemnik@outly.si" });
    assert(r.status === 200, "(e) prenos vstopnice brez pusha: 200", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM ticket_transfers WHERE ticket_id=$1 AND seen_at IS NULL", [nav5.id])).rows[0].n === 1, "(e) vrstica v zvoncu (prenos) je tu");
    r = await apiB("POST", "/events", T.lastnik, { clubId: 1, title: "Brez pusha objava", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
    assert(r.status === 201, "(e) objava dogodka brez pusha: 201", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications WHERE event_id=$1", [r.body.id])).rows[0].n === 2, "(e) vrstice v zvoncu (sledilca) so tu");
    r = await apiB("POST", "/me/devices", T.kupec, { token: zet("brez") });
    assert(r.status === 200, "(e) registracija naprave deluje tudi brez APNs");
    await cakaj(800);
    assert(zahteve.length === 0, "(e) APNs ni prejel NICESAR", zahteve.length);

    // ------------------------------------------------------------------------------------------------------------------
    console.log("\n# Izbris racuna pobrise naprave; zeton in kljuc nikoli v dnevniku");
    const dnevnik = srv.log + brez.log;
    assert(!dnevnik.includes(APNS_P8_B64) && !dnevnik.includes("BEGIN PRIVATE KEY") && !dnevnik.includes(auth.slice(7)) && !dnevnik.includes(js), "dnevnik NE vsebuje kljuca ne JWT");
    assert(![...imeZetona.keys()].some(z => dnevnik.includes(z)), "dnevnik NE vsebuje nobenega zetona naprave");
    assert(/\[push\] table_service: /.test(srv.log), "dnevnik ima povzetek pusha (stevila, brez zetonov)");
    // kaskada: izbris uporabnika (kot DELETE /me) pobrise njegove naprave
    await api("POST", "/me/devices", T.nesledilec, { token: zet("kaskada") });
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens WHERE user_id=$1", [U.nesledilec])).rows[0].n === 2, "nesledilec ima 2 napravi");
    await pool.query("DELETE FROM users WHERE id = $1", [U.nesledilec]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM device_tokens WHERE token IN ($1,$2)", [zet("X1"), zet("kaskada")])).rows[0].n === 0, "ON DELETE CASCADE: izbris racuna pobrise naprave");
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA:", e && e.stack || e);
  }

  srv.proc.kill(); brez.proc.kill(); jwksServer.close(); apnsStreznik.close(); await pool.end().catch(() => {});
  try { fs.rmSync(mapa, { recursive: true, force: true }); } catch { /* ignoriraj */ }
  console.log(`\n${ok} OK, ${fail} napak`);
  if (fail) { console.log("--- dnevnik streznika (zadnjih 3000 znakov) ---\n" + srv.log.slice(-3000)); process.exit(1); }
  process.exit(0);
})();
