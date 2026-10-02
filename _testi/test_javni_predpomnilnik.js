#!/usr/bin/env node
/**
 * Test: javni predpomnilnik seznamov (issue #114, invarianta I17).
 * Zagon (lokalno, PG16, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_javni_predpomnilnik.js
 * Vzorec kot test_vabila.js: lokalni JWKS (3990); backend A (TTL 60 s, torej v testu nikoli ne poteče - vse se zanasa na
 * razveljavitev, test ni obcutljiv na pocasen CI; 20 kljucev) na 3150; backend B (predpomnilnik izklopljen,
 * JAVNI_PREDPOMNILNIK_MS=0) na 3151 = kontrola, da meritve niso prazne; backend C (TTL 2 s, casovna meja single-flight
 * 0,5 s) na 3152 za teste, ki potrebujejo potek casa.
 *
 * Pokrito: (a) osebna polja ne uhajajo med uporabniki/gosta, (b) sprememba je takoj vidna v istem procesu,
 * (c) ETag + 304, (d) 200 hkratnih zahtevkov = 1 poizvedba v bazo (merjeno z zaklepom tabele in pg_stat_activity),
 * (e) omejitev velikosti, plus enotski testi modula (LRU, TTL, razveljavitev med poizvedbo, napake).
 */
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const { ustvariPredpomnilnik } = require("../javni_predpomnilnik");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3150, PORT_B = 3151, PORT_C = 3152, JWKS_PORT = 3990;
const A = `http://127.0.0.1:${PORT_A}`, B = `http://127.0.0.1:${PORT_B}`, C = `http://127.0.0.1:${PORT_C}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-1";
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
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

async function req(osnova, method, pot, { token, body, headers } = {}) {
  const r = await fetch(osnova + pot, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...(headers || {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, body: json, text, headers: r.headers, stanje: r.headers.get("x-predpomnilnik") };
}
// fetch (undici) ob If-None-Match sam doda "Cache-Control: no-cache" (po specifikaciji), zato Express ne vrne 304.
// Pogojni zahtevki gredo prek http.request, ki poslje natanko podane glave (kot URLSession/brskalnik pri revalidaciji).
function surovGet(osnova, pot, glave) {
  return new Promise((resolve, reject) => {
    const u = new URL(osnova + pot);
    const q = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method: "GET", headers: glave }, (res) => {
      const kosi = []; res.on("data", (d) => kosi.push(d));
      res.on("end", () => {
        const text = Buffer.concat(kosi).toString("utf8");
        let json; try { json = JSON.parse(text); } catch { json = text; }
        resolve({ status: res.statusCode, body: json, text, headers: { get: (k) => res.headers[k.toLowerCase()] ?? null }, stanje: res.headers["x-predpomnilnik"] ?? null });
      });
    });
    q.on("error", reject); q.end();
  });
}
const a = (method, pot, token, body, headers) => (method === "GET" && headers
  ? surovGet(A, pot, { ...(token ? { authorization: "Bearer " + token } : {}), ...headers })
  : req(A, method, pot, { token, body, headers }));
const b = (method, pot, token, body) => req(B, method, pot, { token, body });
const cakajoci_zaklep = async (pool) => Number((await pool.query(
  "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()")).rows[0].n);
const osebna = ["my_plan", "friends_going", "friends_interested", "is_following"];

function zazeni(port, dodatnoOkolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", ...dodatnoOkolje }, stdio: ["ignore", "pipe", "pipe"] });
  srv.log = ""; srv.stdout.on("data", d => srv.log += d); srv.stderr.on("data", d => srv.log += d);
  return srv;
}
async function pocakaj(osnova) { for (let i = 0; i < 80; i++) { try { await fetch(osnova + "/"); return; } catch { await spi(100); } } }
function rssMB(pid) { try { return Number(/VmRSS:\s+(\d+) kB/.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"))[1]) / 1024; } catch { return NaN; } }

async function enotski() {
  console.log("\n# Enotski testi modula (poljubna ura, majhne omejitve)");
  let t = 1000;
  const ura = () => t;
  const c = ustvariPredpomnilnik({ ttlMs: 100, najvecKljucev: 3, ura });
  let klici = 0;
  const izr = (vrednost) => async () => { klici++; return { status: 200, json: { v: vrednost } }; };

  let r = await c.dobi("k1", izr(1));
  assert(r.stanje === "zgresitev" && klici === 1, "prva poizvedba = zgresitev");
  r = await c.dobi("k1", izr(2));
  assert(r.stanje === "zadetek" && klici === 1 && JSON.parse(r.vnos.telo).v === 1, "druga znotraj TTL = zadetek, brez nove poizvedbe");
  t += 101;
  r = await c.dobi("k1", izr(3));
  assert(r.stanje === "zgresitev" && klici === 2 && JSON.parse(r.vnos.telo).v === 3, "po TTL nova poizvedba");

  // LRU: omejitev 3 kljuce
  await c.dobi("k2", izr(0)); await c.dobi("k3", izr(0));   // k1,k2,k3
  await c.dobi("k1", izr(0));                                // zadetek -> k1 na konec: k2,k3,k1
  await c.dobi("k4", izr(0));                                // izpodrine najdlje neuporabljenega (k2)
  assert((await c.dobi("k1", izr(0))).stanje === "zadetek", "LRU: pogosto uporabljen k1 ostane");
  assert((await c.dobi("k2", izr(0))).stanje === "zgresitev", "LRU: najdlje neuporabljen k2 je izpodrinjen");
  assert(c.statistika().kljucev <= 3, "stevilo kljucev nikoli > omejitve (3)", c.statistika());
  for (let i = 0; i < 1000; i++) await c.dobi("nakljucen" + i, izr(i));
  assert(c.statistika().kljucev <= 3, "po 1000 razlicnih kljucih se vedno <= 3", c.statistika());

  // Omejitev bajtov
  const cb = ustvariPredpomnilnik({ ttlMs: 1000, najvecKljucev: 1000, najvecBajtov: 5000, ura });
  for (let i = 0; i < 50; i++) await cb.dobi("b" + i, async () => ({ status: 200, json: { x: "y".repeat(1000) } }));
  assert(cb.statistika().bajtov <= 5000, "bajtov nikoli > proracuna", cb.statistika());

  // Single-flight
  const cs = ustvariPredpomnilnik({ ttlMs: 1000, najvecKljucev: 10, ura });
  let n = 0, odpri;
  const vrata = new Promise((res) => { odpri = res; });
  const pocasna = async () => { n++; await vrata; return { status: 200, json: [1, 2, 3] }; };
  const vsi = Array.from({ length: 200 }, () => cs.dobi("sf", pocasna));
  await spi(20); odpri();
  const rez = await Promise.all(vsi);
  assert(n === 1, "200 hkratnih -> 1 poizvedba", n);
  assert(rez.filter((x) => x.stanje === "zgresitev").length === 1 && rez.filter((x) => x.stanje === "zdruzeno").length === 199, "1 zgresitev + 199 zdruzenih");
  assert(rez.every((x) => x.vnos === rez[0].vnos), "vsi dobijo isti vnos");

  // Napaka: ni shranjena, vsi cakajoci jo dobijo, naslednji poskus je nov
  const ce = ustvariPredpomnilnik({ ttlMs: 1000, najvecKljucev: 10, ura });
  let ne = 0;
  const slaba = async () => { ne++; await spi(10); throw new Error("baza"); };
  const sl = await Promise.allSettled([ce.dobi("e", slaba), ce.dobi("e", slaba), ce.dobi("e", slaba)]);
  assert(ne === 1 && sl.every((x) => x.status === "rejected"), "napaka: 1 poizvedba, vsi 3 zavrnjeni", { ne });
  const po = await ce.dobi("e", async () => ({ status: 200, json: 1 }));
  assert(po.stanje === "zgresitev", "po napaki ni zastrupljenega vnosa");
  const ne404 = await ce.dobi("n", async () => ({ status: 404, besedilo: "x" }));
  assert((await ce.dobi("n", async () => ({ status: 404, besedilo: "x" }))).stanje === "zgresitev" && ne404.vnos.etag === null, "404 se ne hrani, brez ETag");

  // Razveljavitev med poizvedbo: rezultat se NE shrani, novi zahtevki se ji ne pridruzijo
  const cr = ustvariPredpomnilnik({ ttlMs: 1000, najvecKljucev: 10, ura });
  let odpri2; const vrata2 = new Promise((res) => { odpri2 = res; });
  const stara = cr.dobi("r", async () => { await vrata2; return { status: 200, json: "staro" }; });
  await spi(10);
  cr.razveljavi();
  const nova = await cr.dobi("r", async () => ({ status: 200, json: "novo" }));
  assert(nova.stanje === "zgresitev" && JSON.parse(nova.vnos.telo) === "novo", "po razveljavitvi se zahtevek ne pridruzi stari poizvedbi");
  odpri2();
  await stara;
  assert(JSON.parse((await cr.dobi("r", async () => ({ status: 200, json: "x" }))).vnos.telo) === "novo", "stara poizvedba (pred razveljavitvijo) ne prepise vnosa");

  // Casovna meja single-flight
  const ct = ustvariPredpomnilnik({ ttlMs: 1000, najvecKljucev: 10, cakanjeMs: 50, ura });
  let nt = 0, sprosti;
  const vrataT = new Promise((res) => { sprosti = res; });
  const vodja = ct.dobi("t", async () => { nt++; await vrataT; return { status: 200, json: "staro" }; });
  await spi(5);
  const cakNiz = await Promise.race([
    Promise.all([1, 2, 3].map(() => ct.dobi("t", async () => { nt++; return { status: 200, json: "novo" }; }))),
    spi(2000).then(() => null)]);
  assert(cakNiz !== null, "casovna meja: cakajoci se ne obesijo za obviselim vodjem");
  const cak = cakNiz || [];
  assert(nt === 2, "casovna meja: vodja + ena nova poizvedba (ne tri)", nt);
  assert(cak.length === 3 && cak.every((x) => JSON.parse(x.vnos.telo) === "novo"), "casovna meja: vsi cakajoci dobijo svez rezultat");
  assert(ct.statistika().casovneMeje === 3, "casovna meja: stevec 3", ct.statistika());
  sprosti(); await vodja;
  const pov = await ct.dobi("t", async () => ({ status: 200, json: "x" }));
  assert(pov.stanje === "zadetek" && JSON.parse(pov.vnos.telo) === "novo", "opuscena stara poizvedba, ki se konca pozneje, ne prepise novejsega vnosa");

  // Loceni proracun za prosto besedilo
  const cp = ustvariPredpomnilnik({ ttlMs: 1000, najvecKljucev: 100, najvecProstih: 3, ura });
  await cp.dobi("vroc", async () => ({ status: 200, json: 1 }));
  for (let i = 0; i < 50; i++) await cp.dobi("p" + i, async () => ({ status: 200, json: i }), { prosto: true });
  assert(cp.statistika().prostih === 3 && (await cp.dobi("vroc", async () => ({ status: 200, json: 2 }))).stanje === "zadetek", "prosti kljuci: najvec 3, vroc kljuc ostane", cp.statistika());
  assert(cp.statistika().kljucev === 4, "prosti kljuci: skupaj 1 + 3", cp.statistika());

  // Porocilo stevcev (za dnevnik)
  const cq = ustvariPredpomnilnik({ ttlMs: 1000, najvecKljucev: 10, ura });
  await cq.dobi("q", async () => ({ status: 200, json: 1 })); await cq.dobi("q", async () => ({ status: 200, json: 1 })); cq.razveljavi();
  let por = cq.porocilo();
  assert(por.zadetki === 1 && por.zgresitve === 1 && por.razveljavitve === 1, "porocilo: delta stevcev", por);
  por = cq.porocilo();
  assert(por.zadetki === 0 && por.razveljavitve === 0, "porocilo: drugi klic = 0 sprememb", por);

  // Izklopljeno
  const ci = ustvariPredpomnilnik({ ttlMs: 0, ura });
  let ni = 0;
  await Promise.all([1, 2, 3].map(() => ci.dobi("i", async () => { ni++; return { status: 200, json: 1 }; })));
  assert(ni === 3 && !ci.omogoceno, "TTL 0: vsak zahtevek svoja poizvedba (izklopljeno)", ni);
}

(async () => {
  await enotski();

  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE view_counts, event_interest, club_event_notifications, club_follows, club_invites, club_members, event_favorites, friendships, friend_requests, ticket_transfers, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  const sA = zazeni(PORT_A, { JAVNI_PREDPOMNILNIK_MS: "60000", JAVNI_PREDPOMNILNIK_KLJUCEV: "20" });
  const sB = zazeni(PORT_B, { JAVNI_PREDPOMNILNIK_MS: "0" });
  const sC = zazeni(PORT_C, { JAVNI_PREDPOMNILNIK_MS: "2000", JAVNI_PREDPOMNILNIK_CAKANJE_MS: "500" });
  await pocakaj(A); await pocakaj(B); await pocakaj(C);
  const c = (method, pot, token, body) => req(C, method, pot, { token, body });

  try {
    const T = {};
    for (const [i, ime] of ["lastnik", "ana", "bor", "cene", "an_x"].entries()) T[ime] = zeton(`${ime}@outly.si`, uuid(i + 1));
    for (const k of Object.keys(T)) { const r = await a("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    const id = {};
    for (const row of (await pool.query("SELECT id, email FROM users")).rows) id[row.email.split("@")[0]] = row.id;
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Pure Club', 'Ljubljana')", [id.lastnik]);
    const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    for (const k of ["ana", "bor", "cene", "an_x"]) await a("PATCH", "/me", T[k], { dateOfBirth: polnoleten, genres: ["house"] });
    async function sprijatelji(x, y) {
      const r = await a("POST", "/me/friends/requests", T[x], { user_id: id[y] });
      if (r.status === 201) await a("POST", `/me/friends/requests/${r.body.request.id}/accept`, T[y]);
    }
    await sprijatelji("ana", "bor");        // ana <-> bor
    await sprijatelji("ana", "cene");       // ana <-> cene; bor in cene NISTA prijatelja; an_x ni nicigar prijatelj

    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    let r = await a("POST", "/events", T.lastnik, { clubId: 1, title: "Zabava", description: "Dolg opis zabave", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
    assert(r.status === 201, "dogodek ustvarjen", r.body);
    const ev = r.body.id;
    r = await a("POST", "/events", T.lastnik, { clubId: 1, title: "Druga", description: "Opis druge", startAt: new Date(Date.now() + 8 * 24 * 3600 * 1000).toISOString(), ticketPriceCents: 500, capacity: 50, minAge: 0 });
    const ev2 = r.body.id;

    // ana, bor, an_x zainteresirani; cene ima vstopnico (going)
    for (const k of ["ana", "bor", "an_x"]) await a("PUT", `/events/${ev}/interest`, T[k]);
    r = await a("POST", `/events/${ev}/orders`, T.cene, { quantity: 1 });
    assert(r.status === 201, "cene kupi vstopnico", r.body);

    console.log("\n# (a) Osebna polja ne uhajajo med uporabniki in na gosta (I17, I11)");
    r = await a("GET", `/events/${ev}`);
    const gostPrvi = r;
    assert(r.status === 200 && r.body.my_plan === null && r.body.friends_going.length === 0 && r.body.friends_interested.length === 0,
      "gost (prvi, polni predpomnilnik): my_plan null, prazna seznama", r.body);
    assert(r.stanje === "zgresitev", "gost: prvi zahtevek = zgresitev", r.stanje);

    r = await a("GET", `/events/${ev}`, T.ana);
    assert(r.status === 200 && r.stanje === "zadetek", "ana: javni del iz predpomnilnika (zadetek)", r.stanje);
    assert(r.body.my_plan === "interested", "ana: my_plan interested", r.body.my_plan);
    assert(r.body.friends_going.map((f) => f.username).join() === "cene", "ana: friends_going = cene", r.body.friends_going);
    assert(r.body.friends_interested.map((f) => f.username).join() === "bor", "ana: friends_interested = bor (an_x ni prijatelj)", r.body.friends_interested);
    const anaTelo = r.text, anaEtag = r.headers.get("etag");

    r = await a("GET", `/events/${ev}`);
    assert(r.text === gostPrvi.text, "gost po anini poizvedbi: telo je BAJT ZA BAJTOM enako kot pred njo", r.body);
    assert(!/bor|cene|avatar_url/.test(JSON.stringify([r.body.friends_going, r.body.friends_interested])) && r.body.my_plan === null, "gost: nobenih tujih imen/avatarjev, my_plan null");

    r = await a("GET", `/events/${ev}`, T.an_x);
    assert(r.body.my_plan === "interested" && r.body.friends_going.length === 0 && r.body.friends_interested.length === 0,
      "an_x (brez prijateljev) ne dobi anine ali borove osebne vsebine", r.body);
    assert(!/"bor"|"cene"|"ana"/.test(r.text.replace(/"title":"[^"]*"/, "")), "an_x: v telesu ni uporabniskih imen drugih", r.text.slice(0, 300));

    r = await a("GET", `/events/${ev}`, T.bor);
    assert(r.body.my_plan === "interested" && r.body.friends_interested.map((f) => f.username).join() === "ana" && r.body.friends_going.length === 0,
      "bor: friends_interested = ana, friends_going prazno (bor in cene nista prijatelja)", r.body);

    r = await a("GET", `/events/${ev}`, T.cene);
    assert(r.body.my_plan === "going" && r.body.friends_interested.map((f) => f.username).join() === "ana", "cene: going + vidi ano", r.body);

    r = await a("GET", `/events/${ev}`, T.ana);
    assert(r.text === anaTelo, "ana ponovno: enak odgovor kot prvic (predpomnilnik ni pokvaril osebnega dela)");

    r = await a("GET", `/events/${ev}`, "to.ni.zeton");
    assert(r.status === 200 && r.text === gostPrvi.text, "neveljaven zeton = gost: enako telo kot gost");

    // Obratna smer: prijavljen uporabnik napolni predpomnilnik PRVI (po zapisu je prazen), gost in tujec berejeta za njim.
    await a("PATCH", `/events/${ev}`, T.lastnik, { title: "Zabava (ana prva)" });
    r = await a("GET", `/events/${ev}`, T.ana);
    assert(r.stanje === "zgresitev" && r.body.my_plan === "interested" && r.body.friends_going.length === 1, "ana napolni predpomnilnik prva (zgresitev), vidi svoje", r.body);
    r = await a("GET", `/events/${ev}`);
    assert(r.stanje === "zadetek" && r.body.my_plan === null && r.body.friends_going.length === 0 && r.body.friends_interested.length === 0,
      "gost za ano: zadetek, brez anine osebne vsebine", r.body);
    assert(!/"cene"|"bor"|avatar_url/.test(r.text), "gost za ano: v telesu ni imen prijateljev", r.text.slice(0, 300));
    r = await a("GET", `/events/${ev}`, T.an_x);
    assert(r.stanje === "zadetek" && r.body.friends_going.length === 0 && r.body.friends_interested.length === 0 && r.body.my_plan === "interested",
      "an_x za ano: ne vidi anine vsebine, vidi samo svoj plan", r.body);

    console.log("\n# Glave: osebna razlicica je private + Vary: Authorization (CDN je ne sme shraniti)");
    const vary = (x) => String(x.headers.get("vary") || "").toLowerCase();
    for (const pot of [`/events/${ev}`, "/clubs/1"]) {
      const g = await a("GET", pot), o = await a("GET", pot, T.ana);
      assert(o.headers.get("cache-control") === "private" && vary(o).includes("authorization"), `${pot}: prijavljen -> Cache-Control: private + Vary: Authorization`, [o.headers.get("cache-control"), vary(o)]);
      assert(g.headers.get("cache-control") === null && vary(g).includes("authorization"), `${pot}: gost -> Vary: Authorization, brez Cache-Control`, [g.headers.get("cache-control"), vary(g)]);
      const o304 = await a("GET", pot, T.ana, null, { "If-None-Match": o.headers.get("etag") });
      assert(o304.status === 304 && o304.headers.get("cache-control") === "private", `${pot}: 304 osebne razlicice je tudi private`);
    }
    for (const pot of ["/events?upcoming=true", "/clubs"]) {
      const l = await a("GET", pot, T.ana);
      assert(l.headers.get("cache-control") === null && !vary(l).includes("authorization"), `${pot}: seznam ostane brez Cache-Control in Vary (enak za vse)`);
    }

    console.log("\n# Razveljavitev: zapisi, ki ne vplivajo na predpomnjene odgovore, je ne sprozijo; stevci jo");
    await a("GET", "/events?upcoming=true"); await a("GET", "/clubs/1"); await a("GET", `/events/${ev}`);
    const ostane = async (opis) => {
      const x = [await a("GET", "/events?upcoming=true"), await a("GET", "/clubs/1"), await a("GET", `/events/${ev}`)];
      assert(x.every((q) => q.stanje === "zadetek"), `${opis}: predpomnilnik ostane (3 zadetki)`, x.map((q) => q.stanje));
    };
    r = await a("PATCH", "/me", T.an_x, { genres: ["techno"] });
    assert(r.status === 200, "PATCH /me", r.status); await ostane("PATCH /me");
    r = await a("PUT", `/me/favorites/${ev}`, T.an_x); assert(r.status < 300, "PUT favorites", r.status);
    r = await a("DELETE", `/me/favorites/${ev}`, T.an_x); assert(r.status < 300, "DELETE favorites", r.status); await ostane("favorites");
    r = await a("POST", "/me/friends/requests", T.an_x, { user_id: id.cene });
    assert(r.status === 201, "an_x -> prosnja za prijateljstvo", r.status);
    r = await a("DELETE", `/me/friends/requests/${r.body.request.id}`, T.an_x); assert(r.status < 300, "preklic prosnje", r.status);
    await ostane("prijateljske prosnje");
    // Stevca (interested_count, followers_count) pa se spreminjata -> razveljavitev
    r = await a("PUT", `/events/${ev}/interest`, T.cene);
    r = await a("GET", `/events/${ev}`);
    assert(r.stanje === "zgresitev" && r.body.interested_count === 4, "PUT interest razveljavi in stevec je takoj tocen (4)", [r.stanje, r.body.interested_count]);
    r = await a("PUT", "/clubs/1/follow", T.bor);
    r = await a("GET", "/clubs/1");
    assert(r.stanje === "zgresitev" && r.body.followers_count === 1, "PUT follow razveljavi in followers_count je takoj tocen (1)", [r.stanje, r.body.followers_count]);
    await a("DELETE", `/events/${ev}/interest`, T.cene); await a("DELETE", "/clubs/1/follow", T.bor);

    // Kljuc ne vsebuje zetona: seznama /events in /clubs sta enaka za vse
    const sezGost = await a("GET", "/events?upcoming=true");
    const sezAna = await a("GET", "/events?upcoming=true", T.ana);
    const sezAnX = await a("GET", "/events?upcoming=true", T.an_x);
    assert(sezGost.text === sezAna.text && sezAna.text === sezAnX.text, "GET /events: isto telo za gosta in prijavljene");
    assert(sezAna.stanje === "zadetek" && sezAnX.stanje === "zadetek", "GET /events z zetonom zadene isti vnos kot gost (kljuc brez zetona)", [sezAna.stanje, sezAnX.stanje]);
    assert(sezGost.body.every((e) => osebna.every((k) => !(k in e))), "GET /events: noben dogodek nima osebnih polj");
    const klGost = await a("GET", "/clubs");
    const klAna = await a("GET", "/clubs", T.ana);
    assert(klGost.text === klAna.text && klAna.stanje === "zadetek", "GET /clubs: isto telo za gosta in prijavljenega, isti vnos");
    assert(klGost.body.every((k) => osebna.every((p) => !(p in k))), "GET /clubs: noben klub nima osebnih polj");

    // /clubs/:id: is_following je osebno
    r = await a("GET", "/clubs/1");
    assert(r.status === 200 && r.body.is_following === false && r.stanje === "zgresitev", "klub: gost is_following false", r.body.is_following);
    const klubGostTelo = r.text;
    r = await a("PUT", "/clubs/1/follow", T.ana);
    assert(r.status === 200 || r.status === 204 || r.status === 201, "ana sledi klubu", r.status);
    r = await a("GET", "/clubs/1", T.ana);
    assert(r.body.is_following === true && r.body.followers_count === 1, "klub: ana is_following true, followers_count 1 takoj", r.body);
    r = await a("GET", "/clubs/1");
    assert(r.body.is_following === false && r.body.followers_count === 1, "klub: gost po anini poizvedbi je se vedno is_following false (followers_count 1)", r.body);
    r = await a("GET", "/clubs/1", T.bor);
    assert(r.body.is_following === false, "klub: bor is_following false (ni anin)", r.body.is_following);
    r = await a("GET", "/clubs/1", T.ana);
    assert(r.body.is_following === true, "klub: ana se vedno true");
    await a("PATCH", "/business/clubs/me", T.lastnik, { description: "ana prva" });
    r = await a("GET", "/clubs/1", T.ana);
    assert(r.stanje === "zgresitev" && r.body.is_following === true, "klub: ana napolni prva, is_following true");
    r = await a("GET", "/clubs/1");
    assert(r.stanje === "zadetek" && r.body.is_following === false, "klub: gost za ano: is_following false");
    r = await a("GET", "/clubs/1", T.an_x);
    assert(r.body.is_following === false, "klub: an_x za ano: is_following false");
    assert(klubGostTelo !== (await a("GET", "/clubs/1")).text, "klub: telo gosta se je po follow spremenilo samo v followers_count (ne vsebuje ane)");

    console.log("\n# Telo je enako kot brez predpomnilnika (B = izklopljen)");
    for (const pot of ["/events?upcoming=true", `/events?clubId=1&upcoming=true`, "/events", "/clubs", "/clubs?withCoords=true", "/clubs?q=pure&limit=5", `/events/${ev}`, "/clubs/1"]) {
      const x = await a("GET", pot), y = await b("GET", pot);
      assert(x.status === y.status && x.text === y.text && x.headers.get("x-total-count") === y.headers.get("x-total-count"),
        `${pot}: telo (in X-Total-Count) enako kot brez predpomnilnika`, [x.status, y.status]);
    }
    r = await b("GET", "/events");
    assert(r.stanje === "izklopljen", "B: stanje izklopljen", r.stanje);
    assert(a && (await a("GET", "/events")).headers.get("cache-control") === null, "Cache-Control: nespremenjen (ni ga bilo, ni ga)");
    r = await a("GET", "/clubs");
    assert(r.headers.get("x-total-count") === "1", "X-Total-Count se vrne tudi iz predpomnilnika", r.headers.get("x-total-count"));

    console.log("\n# Napake niso predpomnjene in imajo enake kode");
    for (const [pot, koda] of [["/events/abc", 400], ["/events/99999", 404], ["/clubs/abc", 400], ["/clubs/99999", 404], ["/events?popular=true", 400], ["/events?clubId=abc", 500]]) {
      const x = await a("GET", pot), y = await b("GET", pot);
      assert(x.status === koda && y.status === koda && x.text === y.text, `${pot} -> ${koda} (enako kot brez predpomnilnika)`, [x.status, y.status]);
    }
    r = await a("GET", "/events/99999");
    assert(r.stanje !== "zadetek", "404 ni zadetek");

    console.log("\n# (b) Sprememba je takoj vidna v istem procesu");
    await a("GET", "/events?upcoming=true"); await a("GET", `/events/${ev}`); await a("GET", "/clubs"); await a("GET", "/clubs/1");
    r = await a("PATCH", `/events/${ev}`, T.lastnik, { title: "Zabava (preimenovana)" });
    assert(r.status === 200, "PATCH /events/:id -> 200", r.body);
    r = await a("GET", `/events/${ev}`);
    assert(r.body.title === "Zabava (preimenovana)" && r.stanje === "zgresitev", "GET /events/:id takoj kaze novi naslov", [r.body.title, r.stanje]);
    r = await a("GET", "/events?upcoming=true");
    assert(r.body.find((e) => e.id === ev).title === "Zabava (preimenovana)", "GET /events takoj kaze novi naslov");
    r = await a("GET", `/events/${ev}`, T.ana);
    assert(r.body.title === "Zabava (preimenovana)" && r.body.my_plan === "interested", "ana: novi naslov + njen plan");

    r = await a("PATCH", "/business/clubs/me", T.lastnik, { name: "Pure Club 2" });
    assert(r.status === 200, "PATCH /business/clubs/me -> 200", r.body);
    r = await a("GET", "/clubs/1"); const r2 = await a("GET", "/clubs");
    assert(r.body.name === "Pure Club 2" && r2.body[0].name === "Pure Club 2", "klub: novo ime takoj v /clubs/:id in /clubs");

    r = await a("POST", "/events", T.lastnik, { clubId: 1, title: "Nova", startAt: new Date(Date.now() + 9 * 24 * 3600 * 1000).toISOString(), minAge: 0 });
    const idNova = r.body.id;
    r = await a("GET", "/events?upcoming=true");
    assert(r.body.some((e) => e.id === idNova), "novi dogodek je takoj na seznamu");
    r = await a("DELETE", `/events/${idNova}`, T.lastnik);
    assert(r.status === 200 || r.status === 204, "DELETE /events/:id", r.status);
    r = await a("GET", "/events?upcoming=true");
    assert(!r.body.some((e) => e.id === idNova), "izbrisan dogodek takoj izgine s seznama");

    // Skrit klub (admin panel) javno izgine takoj, tudi iz predpomnilnika
    await pool.query("UPDATE users SET role='admin' WHERE email='an_x@outly.si'");
    await a("GET", "/clubs"); await a("GET", "/clubs/1"); await a("GET", `/events/${ev}`); await a("GET", "/events?upcoming=true");
    r = await a("PATCH", "/admin/api/clubs/1", T.an_x, { hidden: true });
    assert(r.status === 200, "admin skrije klub", r.body);
    const skrit = [(await a("GET", "/clubs")), (await a("GET", "/clubs/1")), (await a("GET", `/events/${ev}`)), (await a("GET", "/events?upcoming=true"))];
    assert(skrit[0].body.length === 0 && skrit[1].status === 404 && skrit[2].status === 404 && skrit[3].body.length === 0,
      "skrit klub in njegovi dogodki takoj izginejo iz /clubs, /clubs/:id, /events/:id in /events", skrit.map((x) => x.status));
    r = await a("PATCH", "/admin/api/clubs/1", T.an_x, { hidden: false });
    r = await a("GET", "/clubs/1");
    assert(r.status === 200, "ponovno viden klub je takoj spet na voljo", r.status);
    await pool.query("UPDATE users SET role='user' WHERE email='an_x@outly.si'");

    r = await a("POST", `/events/${ev2}/orders`, T.ana, { quantity: 2 });
    assert(r.status === 201, "nakup 2 vstopnic", r.body);
    r = await a("GET", `/events/${ev2}`);
    assert(r.body.sold_count === 2, "sold_count se po nakupu takoj vidi v /events/:id", r.body.sold_count);
    r = await a("GET", "/events?upcoming=true");
    assert(r.body.find((e) => e.id === ev2).sold_count === 2, "... in v /events");
    r = await a("PUT", `/events/${ev2}/interest`, T.bor);
    r = await a("GET", `/events/${ev2}`);
    assert(r.body.interested_count === 1, "interested_count takoj po PUT interest", r.body.interested_count);

    console.log("\n# Zahtevki, ki niso spremenili podatkov, predpomnilnika ne izpraznijo");
    await a("GET", "/events?upcoming=true");
    r = await a("POST", "/events", null, { clubId: 1, title: "x" });
    assert(r.status === 401, "POST /events brez zetona -> 401");
    r = await a("PATCH", `/events/${ev}`, T.ana, { title: "Vdor" });
    assert(r.status >= 400 && r.status < 500, "PATCH s tujim uporabnikom (ni clan kluba) -> 4xx", r.status);
    r = await a("POST", "/views", null, { club_id: 1 });
    assert(r.status === 204 || r.status === 200 || r.status === 201, "POST /views", r.status);
    r = await a("GET", "/events?upcoming=true");
    assert(r.stanje === "zadetek", "po 401, 4xx in POST /views je GET /events se vedno zadetek", r.stanje);

    console.log("\n# Neposredna sprememba baze (druga instanca) zaostane najvec TTL (sprejeto; backend C, TTL 2 s)");
    await c("GET", "/events?upcoming=true");
    await pool.query("UPDATE events SET title = 'Neposredno v bazi' WHERE id = $1", [ev2]);
    r = await c("GET", "/events?upcoming=true");
    assert(r.stanje === "zadetek" && r.body.find((e) => e.id === ev2).title !== "Neposredno v bazi", "znotraj TTL se neposredna sprememba se ne vidi (zadetek)", r.stanje);
    await spi(2300);
    r = await c("GET", "/events?upcoming=true");
    assert(r.stanje === "zgresitev" && r.body.find((e) => e.id === ev2).title === "Neposredno v bazi", "po TTL (2 s) se vidi", [r.stanje]);
    await a("PATCH", `/events/${ev2}`, T.lastnik, { title: "Druga" });   // A je neposredno spremembo zamudil (TTL 60 s): zapis ga uskladi

    console.log("\n# (c) ETag in 304");
    r = await a("GET", "/events?upcoming=true");
    const etag = r.headers.get("etag");
    assert(/^W\/"[A-Za-z0-9_-]{27}"$/.test(etag || ""), "ETag je prisoten (odtis telesa)", etag);
    let r304 = await a("GET", "/events?upcoming=true", null, null, { "If-None-Match": etag });
    assert(r304.status === 304 && r304.text === "", "If-None-Match z veljavnim ETag -> 304, prazno telo", r304.status);
    assert(r304.stanje === "zadetek", "304 iz predpomnilnika", r304.stanje);
    r304 = await a("GET", "/events?upcoming=true", null, null, { "If-None-Match": `W/"drug", ${etag}` });
    assert(r304.status === 304, "seznam v If-None-Match -> 304");
    r304 = await a("GET", "/events?upcoming=true", null, null, { "If-None-Match": 'W/"nekaj-drugega"' });
    assert(r304.status === 200 && r304.text.length > 100, "napacen ETag -> 200 s telesom");
    r304 = await a("GET", "/events?upcoming=true", null, null, { "If-None-Match": etag, "Cache-Control": "no-cache" });
    assert(r304.status === 200, "Cache-Control: no-cache v zahtevku -> 200");
    const brezPredpomnilnika = await b("GET", "/events?upcoming=true");
    assert(brezPredpomnilnika.headers.get("etag") !== null && brezPredpomnilnika.status === 200, "B (izklopljen) tudi vrne ETag (Express), zato ni regresije za odjemalce");
    r = await a("GET", "/clubs");
    const etagK = r.headers.get("etag");
    r304 = await a("GET", "/clubs", null, null, { "If-None-Match": etagK });
    assert(r304.status === 304 && r304.headers.get("x-total-count") === "1", "GET /clubs: 304 (z X-Total-Count)");
    // Po spremembi star ETag ne zadene
    await a("PATCH", `/events/${ev}`, T.lastnik, { title: "Zabava 3" });
    r = await a("GET", "/events?upcoming=true", null, null, { "If-None-Match": etag });
    assert(r.status === 200 && r.headers.get("etag") !== etag, "po spremembi star ETag -> 200 z novim ETag");
    // /events/:id: gost proti prijavljenemu
    const eg = await a("GET", `/events/${ev}`);
    const ep = await a("GET", `/events/${ev}`, T.ana);
    assert(eg.headers.get("etag") !== ep.headers.get("etag"), "ETag gosta != ETag ane (razlicno telo)");
    r = await a("GET", `/events/${ev}`, null, null, { "If-None-Match": eg.headers.get("etag") });
    assert(r.status === 304, "gost: 304 z lastnim ETag");
    r = await a("GET", `/events/${ev}`, T.ana, null, { "If-None-Match": eg.headers.get("etag") });
    assert(r.status === 200 && r.body.my_plan === "interested", "ana z GOSTOVIM ETag dobi 200 s svojimi polji (ne 304)");
    r = await a("GET", `/events/${ev}`, T.ana, null, { "If-None-Match": ep.headers.get("etag") });
    assert(r.status === 304, "ana z lastnim ETag -> 304");

    console.log("\n# Lahek seznam (?lite=true): brez description, privzeto nespremenjeno");
    const polni = await a("GET", "/events?upcoming=true");
    const lahki = await a("GET", "/events?upcoming=true&lite=true");
    assert(polni.body.every((e) => typeof e.description === "string" || e.description === null) && polni.body.some((e) => e.description),
      "privzeto: description je se vedno v odgovoru");
    assert(lahki.status === 200 && lahki.body.length === polni.body.length && lahki.body.every((e) => !("description" in e)), "lite=true: nobenega description");
    const brez = (e) => { const { description, ...ostalo } = e; return ostalo; };
    assert(JSON.stringify(lahki.body) === JSON.stringify(polni.body.map(brez)), "lite = polni brez description (isti vrstni red in polja)");
    assert(lahki.text.length < polni.text.length, "lite je krajsi", [lahki.text.length, polni.text.length]);
    assert((await a("GET", "/events?upcoming=true&lite=true")).stanje === "zadetek" && (await a("GET", "/events?upcoming=true")).stanje === "zadetek",
      "lite in polni imata loceni vnos (oba zadetka)");
    const lahkiB = await b("GET", "/events?upcoming=true&lite=true");
    assert(lahkiB.text === lahki.text, "lite: enako z in brez predpomnilnika");
    r = await a("GET", `/events?clubId=1&popular=true&lite=true`);
    assert(r.status === 200, "popular + lite -> 200", r.status);
    r = await a("GET", "/events?upcoming=true&lite=nesmisel");
    assert(r.body.every((e) => "description" in e), "lite z drugo vrednostjo od 'true' = polni odgovor");

    console.log("\n# (d) 200 hkratnih zahtevkov = 1 poizvedba v bazo (zaklep tabele + pg_stat_activity)");
    const cakajoci = async () => Number((await pool.query(
      "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()")).rows[0].n);
    async function meritev(osnova, pot, tabela, pricakuj) {
      const k = await pool.connect();
      try {
        await k.query("BEGIN");
        await k.query(`LOCK TABLE ${tabela} IN ACCESS EXCLUSIVE MODE`);
        const vsi = Array.from({ length: 200 }, () => req(osnova, "GET", pot));
        await spi(700);
        const n = await cakajoci();
        await k.query("COMMIT");
        const odgovori = await Promise.all(vsi);
        return { n, odgovori };
      } finally { k.release(); }
    }
    await a("PATCH", `/events/${ev}`, T.lastnik, { title: "Zabava 4" });   // zapis izprazni predpomnilnik: noben kljuc spodaj ni vroc
    let m = await meritev(A, "/events?clubId=1&upcoming=true", "events");
    assert(m.n === 1, "A: v bazi caka na zaklep natanko 1 poizvedba (single-flight)", m.n);
    assert(m.odgovori.every((x) => x.status === 200 && x.text === m.odgovori[0].text), "A: vseh 200 odgovorov 200 in enakih");
    const st = (o) => o.reduce((acc, x) => (acc[x.stanje] = (acc[x.stanje] || 0) + 1, acc), {});
    assert(st(m.odgovori).zgresitev === 1 && (st(m.odgovori).zdruzeno || 0) + (st(m.odgovori).zadetek || 0) === 199, "A: 1 zgresitev + 199 zdruzenih/zadetkov", st(m.odgovori));

    // Znotraj TTL zaklep sploh ne moti: odgovor pride iz predpomnilnika (takoj za meritvijo, TTL se steje od zacetka poizvedbe)
    {
      const k = await pool.connect();
      try {
        await k.query("BEGIN"); await k.query("LOCK TABLE events IN ACCESS EXCLUSIVE MODE");
        const vsi = Array.from({ length: 200 }, () => req(A, "GET", "/events?clubId=1&upcoming=true"));
        const izid = await Promise.race([Promise.all(vsi).then((x) => x), spi(2000).then(() => null)]);
        const n = await cakajoci();
        assert(izid !== null && izid.every((x) => x.status === 200 && x.stanje === "zadetek"), "A: 200 zahtevkov znotraj TTL se zakljuci medtem ko je tabela zaklenjena = 0 poizvedb", izid && st(izid));
        assert(n === 0, "A: nobena poizvedba ne caka na zaklep", n);
        await k.query("COMMIT");
      } finally { k.release(); }
    }

    m = await meritev(B, "/events?clubId=1&upcoming=true", "events");
    assert(m.n > 1, "B (kontrola, brez predpomnilnika): vec hkratnih poizvedb caka na zaklep, torej meritev ni prazna", m.n);

    m = await meritev(A, "/clubs?city=Ljubljana", "clubs");
    assert(m.n === 1, "A: GET /clubs: natanko 1 poizvedba caka (COUNT; druga sledi)", m.n);
    assert(m.odgovori.every((x) => x.status === 200), "A: /clubs vseh 200 -> 200");
    await a("PATCH", `/events/${ev}`, T.lastnik, { title: "Zabava 5" });
    m = await meritev(A, `/events/${ev}`, "events");
    assert(m.n === 1, "A: GET /events/:id (gosti): natanko 1 poizvedba", m.n);
    await a("PATCH", `/events/${ev}`, T.lastnik, { title: "Zabava 6" });
    m = await meritev(A, "/clubs/1", "clubs");
    assert(m.n === 1, "A: GET /clubs/:id (gosti): natanko 1 poizvedba", m.n);

    console.log("\n# Casovna meja single-flight (backend C, 0,5 s): obviselo poizvedbo kljuc spusti, cakajoci poskusijo sami");
    await c("PATCH", `/events/${ev}`, T.lastnik, { title: "C zacetek" });
    {
      const k = await pool.connect();
      try {
        await k.query("BEGIN"); await k.query("LOCK TABLE events IN ACCESS EXCLUSIVE MODE");
        const vodja = req(C, "GET", "/events?clubId=1&upcoming=false");
        await spi(150);
        const cakajoci = [1, 2, 3].map(() => req(C, "GET", "/events?clubId=1&upcoming=false"));
        await spi(1000);                                   // cakajoci so po 0,5 s opustili vodjo
        const n = await cakajoci_zaklep(pool);
        assert(n === 2, "obvisela poizvedba vodje + ENA nova (ne 4): cakajoci so se zdruzili v novega vodjo", n);
        await k.query("COMMIT");
        const vsi = await Promise.all([vodja, ...cakajoci]);
        assert(vsi.every((x) => x.status === 200), "po sprostitvi zaklepa vsi 4 dobijo 200", vsi.map((x) => x.status));
      } finally { k.release(); }
    }

    console.log("\n# (e) Omejitev velikosti (JAVNI_PREDPOMNILNIK_KLJUCEV=20) in loceni proracun za prosto besedilo");
    const rss0 = rssMB(sA.pid);
    for (let i = 0; i < 40; i++) await a("GET", `/clubs?offset=${i}`);
    let zadetki = 0;
    for (let i = 39; i >= 20; i--) if ((await a("GET", `/clubs?offset=${i}`)).stanje === "zadetek") zadetki++;
    assert(zadetki === 20, "po 40 razlicnih kljucih je v predpomnilniku natanko zadnjih 20 (omejitev)", zadetki);
    r = await a("GET", "/clubs?offset=19");
    assert(r.stanje === "zgresitev", "21. najnovejsi kljuc je izpodrinjen (LRU)", r.stanje);
    r = await a("GET", "/clubs?q=pure");
    assert(r.status === 200 && r.stanje === "izklopljen", "iskanje q se ne predpomni (gre mimo)", r.stanje);
    // city je prosto besedilo: poplava mest izpodriva samo druge proste kljuce (proracun 10 % kljucev), ne vrocih
    await a("GET", "/clubs?offset=39");
    for (let i = 0; i < 100; i++) await a("GET", `/clubs?city=mesto${i}`);
    r = await a("GET", "/clubs?offset=39");
    assert(r.stanje === "zadetek", "vroc kljuc preziv poplavo 100 razlicnih mest", r.stanje);
    let mest = 0;
    for (let i = 99; i >= 98; i--) if ((await a("GET", `/clubs?city=mesto${i}`)).stanje === "zadetek") mest++;
    assert(mest === 2, "od prostih kljucev sta ostala natanko zadnja 2 (10 % od 20 kljucev)", mest);
    r = await a("GET", "/clubs?city=mesto97");
    assert(r.stanje === "zgresitev", "3. najnovejsi prosti kljuc je izpodrinjen", r.stanje);
    // Poplava z razlicnimi parametri (napad): 1500 zahtevkov, vsak svoj kljuc, dolgi nizi
    const kosi = [];
    for (let i = 0; i < 1500; i++) kosi.push(req(A, "GET", `/clubs?city=${i}-${"x".repeat(90)}&offset=${i % 500}`).then((x) => x.status));
    for (let i = 0; i < kosi.length; i += 100) await Promise.all(kosi.slice(i, i + 100));
    const statusiPoplave = await Promise.all(kosi);
    assert(statusiPoplave.every((s) => s === 200), "poplava 1500 razlicnih kljucev: vsi 200");
    console.log(`  (informativno) RSS backenda A: ${rss0.toFixed(0)} -> ${rssMB(sA.pid).toFixed(0)} MB; trda omejitev je v enotskih testih (kljucev, bajtov)`);
    r = await a("GET", "/clubs?q=" + "z".repeat(150));
    assert(r.status === 200 && r.stanje === "izklopljen", "predolg niz (>100 znakov) gre mimo predpomnilnika", r.stanje);
    r = await a("GET", "/clubs?q=a&q=b");
    assert(r.status === 200 && r.stanje === "izklopljen", "ponovljen parameter (seznam) gre mimo predpomnilnika", r.stanje);
    r = await a("GET", "/clubs?q[x]=1");
    assert(r.status === 200 && r.stanje === "izklopljen", "objekt v parametru gre mimo predpomnilnika", r.stanje);
    r = await a("GET", "/events?upcoming[]=true");
    assert(r.status === 200 && r.stanje === "izklopljen", "seznam v parametru /events gre mimo predpomnilnika", r.stanje);
    r = await a("GET", "/events/" + "1".repeat(40));
    assert(r.status === (await b("GET", "/events/" + "1".repeat(40))).status && r.stanje !== "zadetek", "predolg id gre mimo predpomnilnika (isti odziv kot brez njega)", [r.status, r.stanje]);

    console.log("\n# Brez neujetih napak v dnevniku");
    assert(!/Unhandled|TypeError|ReferenceError/.test(sA.log), "dnevnik A brez neujetih napak", sA.log.slice(-400));
    assert(!/Unhandled|TypeError|ReferenceError/.test(sB.log) && !/Unhandled|TypeError|ReferenceError/.test(sC.log), "dnevnika B in C brez neujetih napak");
  } finally {
    sA.kill(); sB.kill(); sC.kill(); jwksServer.close();
    await pool.end().catch(() => {});
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
