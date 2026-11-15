#!/usr/bin/env node
/**
 * Preklic Applovih zetonov ob izbrisu racuna (Issue #427; ARCHITECTURE »Prijava z Googlom in Applom« tocka 8, I74).
 * Zagon: DATABASE_URL="postgres://postgres@localhost:5447/postgres" node _testi/test_apple_preklic.js
 *
 * Lazni »Supabase« (JWKS, /auth/v1/user, /settings, /token?grant_type=password, /rest/v1/rpc/delete_my_account) na 3872,
 * lazni »Apple« (/auth/token, /auth/revoke) na 3873 prek APPLE_AUTH_URL, backend z okoljem Apple na 3871,
 * backend brez okolja na 3874, backend z neveljavnim kljucem na 3875. Testni EC kljuc (P-256) se generira v testu.
 * Obnasanje laznega Appla doloci koda sama (vsebuje »grant«, »visi«, »pada«, »brezrefresh«, »revoke5xx«, »revoke400«).
 * Negativni primeri (Applu nic) se preverijo na koncu: koda se ne sme pojaviti med klici laznega Appla (vrstni red: klic gre
 * pred odgovor 200, zadnji pozitivni primer pa caka svoj klic z rokom) - brez fiksnega cakanja.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3871, STUB_PORT = 3872, APPLE_PORT = 3873, PORT_BREZ = 3874, PORT_SLAB = 3875;
const kp = () => crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const { publicKey, privateKey } = kp();
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-apple";
const apple = kp();   // Applov kljuc .p8 (testni)
const P8_B64 = Buffer.from(apple.privateKey.export({ format: "pem", type: "pkcs8" })).toString("base64");
const TEAM = "TEAMTEST01", KEY_ID = "KEYTEST001", CLIENT = "si.outly.app";

// ---------------------------------------------------------------- lazni Supabase
const stub = { rpc: 0, geslo: 0 };
const stubServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) {
    let sub = "?", email = "?";
    try { const p = JSON.parse(Buffer.from(String(req.headers.authorization || "").split(".")[1], "base64url")); sub = p.sub; email = p.email; } catch (_) {}
    return res.end(JSON.stringify({ id: sub, email, email_confirmed_at: "2026-11-14T10:00:00Z" }));
  }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  if (req.url.startsWith("/auth/v1/token")) { stub.geslo++; return res.end("{}"); }
  if (req.url.startsWith("/rest/v1/rpc/delete_my_account")) { stub.rpc++; return res.end("{}"); }
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});

// ---------------------------------------------------------------- lazni Apple
const appleKlici = [];   // { pot, polja, cas }
const visece = [];
const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
const revokeStevec = new Map();
const appleServer = http.createServer((req, res) => {
  let telo = "";
  req.on("data", (d) => telo += d);
  req.on("end", () => {
    const polja = Object.fromEntries(new URLSearchParams(telo));
    appleKlici.push({ pot: req.url, polja, ct: req.headers["content-type"], cas: Date.now() });
    const odg = (status, obj) => { res.statusCode = status; res.setHeader("content-type", "application/json"); res.end(obj === undefined ? "" : JSON.stringify(obj)); };
    if (req.url === "/auth/token") {
      const k = polja.code || "";
      if (k.includes("visi")) { visece.push(res); return; }                                  // nikoli ne odgovori (casovna meja 8 s)
      if (k.includes("pada")) { req.socket.destroy(); return; }                              // nedosegljiv / prekinjena povezava
      if (k.includes("grant")) return odg(400, { error: "invalid_grant", error_description: "SKRIVNOSTopis" });
      if (k.includes("cudna")) return odg(400, { error: "SKRIVNOSTnapaka@primer.si" });   // neznana koda napake -> »drugo«
      const id_token = [b64u({ alg: "RS256", kid: "x" }), b64u({ iss: "https://appleid.apple.com", aud: CLIENT, sub: "001234.SKRIVNOSTsub.0001", email: "SKRIVNOST@privaterelay.appleid.com" }), "SKRIVNOSTpodpis"].join(".");
      const t = { access_token: "a.SKRIVNOSTdostop." + k, token_type: "Bearer", expires_in: 3600, id_token };
      if (!k.includes("brezrefresh")) t.refresh_token = "r.SKRIVNOSTosvezitev." + k;
      return odg(200, t);
    }
    if (req.url === "/auth/revoke") {
      const tok = polja.token || "";
      const n = (revokeStevec.get(tok) || 0) + 1; revokeStevec.set(tok, n);
      if (tok.includes("revoke5xx") && n === 1) return odg(503, { error: "SKRIVNOST" });
      if (tok.includes("revoke400")) return odg(400, { error: "invalid_client" });
      return odg(200);
    }
    odg(404, {});
  });
});

// ---------------------------------------------------------------- pomocniki
function zeton(sub, email, amr) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${STUB_PORT}/auth/v1`, aud: "authenticated", sub, email, role: "authenticated", exp: now + 3600, iat: now,
    app_metadata: { provider: "apple", providers: ["apple"] }, user_metadata: { email_verified: true }, amr, is_anonymous: false });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const zdaj = () => Math.floor(Date.now() / 1000);
const oauth = (pred) => [{ method: "oauth", timestamp: zdaj() - pred }];
const pocakaj = async (pogoj, rokMs) => { const konec = Date.now() + rokMs; while (Date.now() < konec) { if (pogoj()) return true; await new Promise((r) => setTimeout(r, 25)); } return pogoj(); };
const klici = (pot, koda) => appleKlici.filter((k) => k.pot === pot && (koda === undefined || k.polja.code === koda || (k.polja.token || "").endsWith("." + koda)));

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

function zazeni(port, env) {
  const s = { log: "" };
  s.proc = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${STUB_PORT}`,
    SUPABASE_PUBLISHABLE_KEY: "sb_publishable_testni_kljuc", RESEND_API_KEY: "", QR_SECRET: "test", SENTRY_DSN: "",
    APPLE_TEAM_ID: "", APPLE_SIWA_KEY_ID: "", APPLE_SIWA_KEY_P8: "", APPLE_SIWA_CLIENT_ID: "", APPLE_AUTH_URL: "", ...env }, stdio: ["ignore", "pipe", "pipe"] });
  s.proc.stdout.on("data", (d) => s.log += d); s.proc.stderr.on("data", (d) => s.log += d);
  return s;
}
async function gor(port) { for (let i = 0; i < 80; i++) { try { await fetch(`http://127.0.0.1:${port}/`); return; } catch { await new Promise((r) => setTimeout(r, 100)); } } throw new Error("backend " + port + " ni gor"); }

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => stubServer.listen(STUB_PORT, r));
  await new Promise((r) => appleServer.listen(APPLE_PORT, r));
  const APPLE_ENV = { APPLE_TEAM_ID: TEAM, APPLE_SIWA_KEY_ID: KEY_ID, APPLE_SIWA_KEY_P8: P8_B64, APPLE_AUTH_URL: `http://127.0.0.1:${APPLE_PORT}` };
  const glavni = zazeni(PORT, APPLE_ENV);
  const brez = zazeni(PORT_BREZ, { APPLE_AUTH_URL: `http://127.0.0.1:${APPLE_PORT}` });
  const slab = zazeni(PORT_SLAB, { ...APPLE_ENV, APPLE_SIWA_KEY_P8: Buffer.from("-----BEGIN PRIVATE KEY-----\nSKRIVNOSTpokvarjen\n-----END PRIVATE KEY-----\n").toString("base64") });
  await Promise.all([gor(PORT), gor(PORT_BREZ), gor(PORT_SLAB)]);

  const api = async (port, method, path, token, body) => {
    await pool.query("TRUNCATE omejitve");   // omejevalnik DELETE /me: 5 na uro
    const r = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { authorization: "Bearer " + token, ...(body !== undefined ? { "content-type": "application/json" } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j };
  };
  let st = 1;
  const racun = async (port = PORT, amr = oauth(10)) => {
    const n = st++; const email = `a${n}@privaterelay.appleid.com`, sub = uuid(n);
    const r = await api(port, "GET", "/me", zeton(sub, email, amr));
    if (r.status !== 200) throw new Error("GET /me " + JSON.stringify(r));
    return { sub, email, id: r.body.id };
  };
  const obstaja = async (id) => (await pool.query("SELECT 1 FROM users WHERE id=$1", [id])).rows.length === 1;
  const izbris = async (u, polja, port = PORT, amr = oauth(10)) => api(port, "DELETE", "/me", zeton(u.sub, u.email, amr), polja);
  const negativne = [];   // kode, ki Applu NE smejo priti

  console.log("\n# (0) zagon: opozorila v dnevniku");
  assert(!/\[apple\] preklic zetonov izklopljen/.test(glavni.log), "z okoljem: brez opozorila »izklopljen«", glavni.log.slice(0, 400));
  assert((brez.log.match(/\[apple\] preklic zetonov izklopljen: manjka/g) || []).length === 1, "brez okolja: ENO opozorilo »[apple] preklic zetonov izklopljen: manjka …«", brez.log.slice(0, 600));
  assert((slab.log.match(/\[apple\] preklic zetonov izklopljen: kljuc ni veljaven/g) || []).length === 1, "neveljaven kljuc: ENO opozorilo »kljuc ni veljaven«", slab.log.slice(0, 600));

  console.log("\n# (1) Apple visi: izbris 200 takoj (odgovor ne caka Appla)");
  let u = await racun();
  let t0 = Date.now();
  let r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.visi.1" });
  const visiOd = Date.now();
  assert(r.status === 200 && r.body.message === "Account deleted." && Date.now() - t0 < 2000, "200 Account deleted. v < 2 s", { r, ms: Date.now() - t0 });
  assert(await pocakaj(() => klici("/auth/token", "c.visi.1").length === 1, 3000), "/auth/token poklican (visi)");

  console.log("\n# (2) srecna pot: /auth/token (obrazec, client_secret JWT) -> /auth/revoke z refresh_token");
  u = await racun();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.SKRIVNOSTkoda.ok" });
  assert(r.status === 200 && r.body.message === "Account deleted." && !(await obstaja(u.id)), "200 Account deleted., vrstica izbrisana", r);
  assert(await pocakaj(() => klici("/auth/revoke", "c.SKRIVNOSTkoda.ok").length === 1, 3000), "/auth/revoke poklican");
  const tk = klici("/auth/token", "c.SKRIVNOSTkoda.ok");
  assert(tk.length === 1, "/auth/token poklican enkrat", tk.length);
  const f = tk[0] ? tk[0].polja : {};
  assert(/application\/x-www-form-urlencoded/.test(tk[0] && tk[0].ct), "content-type form-urlencoded", tk[0] && tk[0].ct);
  assert(f.client_id === CLIENT && f.grant_type === "authorization_code" && f.code === "c.SKRIVNOSTkoda.ok" && !("redirect_uri" in f),
    "token: client_id=si.outly.app, grant_type=authorization_code, code, BREZ redirect_uri", Object.keys(f));
  assert(Object.keys(f).sort().join(",") === "client_id,client_secret,code,grant_type", "token: samo stiri polja", Object.keys(f));
  const [h64, p64, s64] = String(f.client_secret || "").split(".");
  let glava = {}, telo = {};
  try { glava = JSON.parse(Buffer.from(h64, "base64url")); telo = JSON.parse(Buffer.from(p64, "base64url")); } catch (_) {}
  const podpisOk = !!s64 && crypto.verify("sha256", Buffer.from(h64 + "." + p64), { key: apple.publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(s64, "base64url"));
  assert(podpisOk, "client_secret: podpis ES256 preverjen z javnim kljucem .p8");
  assert(glava.alg === "ES256" && glava.kid === KEY_ID, "client_secret glava: alg ES256, kid = APPLE_SIWA_KEY_ID", glava);
  assert(telo.iss === TEAM && telo.sub === CLIENT && telo.aud === "https://appleid.apple.com", "client_secret telo: iss = Team ID, sub = client_id, aud = https://appleid.apple.com", telo);
  assert(Number.isInteger(telo.iat) && Number.isInteger(telo.exp) && telo.exp > telo.iat && telo.exp - telo.iat <= 15777000 && Math.abs(telo.iat - zdaj()) < 60,
    "client_secret: iat ~ zdaj, 0 < exp-iat <= 15777000 (6 mesecev)", { iat: telo.iat, exp: telo.exp });
  const rv = klici("/auth/revoke", "c.SKRIVNOSTkoda.ok")[0] || { polja: {} };
  assert(rv.polja.client_id === CLIENT && rv.polja.token === "r.SKRIVNOSTosvezitev.c.SKRIVNOSTkoda.ok" && rv.polja.token_type_hint === "refresh_token" && !!rv.polja.client_secret,
    "revoke: client_id, client_secret, token = refresh_token, token_type_hint=refresh_token", Object.keys(rv.polja));

  console.log("\n# (3) invalid_grant: izbris 200, revoke NI klican");
  u = await racun();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.grant.1" });
  assert(r.status === 200 && !(await obstaja(u.id)), "200, vrstica izbrisana", r);
  assert(await pocakaj(() => /\[apple\] preklic ni uspel: korak=token status=400 napaka=invalid_grant/.test(glavni.log), 3000), "dnevnik: korak=token status=400 napaka=invalid_grant");
  assert(klici("/auth/token", "c.grant.1").length === 1 && klici("/auth/revoke", "c.grant.1").length === 0, "token enkrat (brez ponovitve), revoke 0");

  console.log("\n# (4) Apple nedosegljiv (prekinjena povezava): izbris 200, dnevnik korak=token");
  u = await racun();
  t0 = Date.now();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.pada.1" });
  assert(r.status === 200 && Date.now() - t0 < 2000, "200 v < 2 s", r);
  assert(await pocakaj(() => /\[apple\] preklic ni uspel: korak=token status=omrezje/.test(glavni.log), 3000), "dnevnik: korak=token status=omrezje");
  assert(klici("/auth/token", "c.pada.1").length === 1, "token brez ponovitve (koda je enkratna)", klici("/auth/token", "c.pada.1").length);

  console.log("\n# (5) neznana Applova napaka -> »drugo« (besedilo Appla ne gre v dnevnik)");
  u = await racun();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.cudna.1" });
  assert(r.status === 200, "200", r);
  assert(await pocakaj(() => /korak=token status=400 napaka=drugo/.test(glavni.log), 3000), "dnevnik: napaka=drugo");

  console.log("\n# (6) brez refresh_token -> revoke z access_token, token_type_hint=access_token");
  u = await racun();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.brezrefresh.1" });
  assert(r.status === 200, "200", r);
  assert(await pocakaj(() => klici("/auth/revoke", "c.brezrefresh.1").length === 1, 3000), "revoke poklican");
  const rv2 = (klici("/auth/revoke", "c.brezrefresh.1")[0] || { polja: {} }).polja;
  assert(rv2.token === "a.SKRIVNOSTdostop.c.brezrefresh.1" && rv2.token_type_hint === "access_token", "token = access_token, hint access_token", rv2.token_type_hint);

  console.log("\n# (7) revoke 503 -> ENA ponovitev; revoke 400 -> brez ponovitve");
  u = await racun();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.revoke5xx.1" });
  assert(r.status === 200, "200", r);
  assert(await pocakaj(() => klici("/auth/revoke", "c.revoke5xx.1").length === 2, 5000), "revoke 2x (503, nato 200)", klici("/auth/revoke", "c.revoke5xx.1").length);
  u = await racun();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.revoke400.1" });
  assert(await pocakaj(() => /korak=revoke status=400 napaka=invalid_client/.test(glavni.log), 3000), "dnevnik: korak=revoke status=400 napaka=invalid_client");
  assert(klici("/auth/revoke", "c.revoke400.1").length === 1, "revoke 400: brez ponovitve");

  console.log("\n# (8) pot z geslom + koda: preklic tudi tu, odgovor nespremenjen");
  u = await racun(PORT, [{ method: "password", timestamp: zdaj() - 5 }]);
  r = await izbris(u, { password: "pravo", apple_authorization_code: "c.geslo.1" }, PORT, undefined);
  assert(r.status === 200 && r.body.message === "Account deleted." && stub.geslo >= 1, "geslo + koda: 200 Account deleted.", r);
  assert(await pocakaj(() => klici("/auth/revoke", "c.geslo.1").length === 1, 3000), "geslo + koda: revoke poklican");

  console.log("\n# (9) brez polja / neveljavna oblika -> izbris 200, Applu nic");
  const neveljavne = [["ni niz (stevilo)", 12345], ["polje", ["c.polje.1"]], ["prazno", ""], ["predolgo (1025)", "c.predolgo." + "x".repeat(1014)],
    ["nedovoljen znak (presledek)", "c.presledek 1"], ["nedovoljen znak (&)", "c.amp&grant_type=x"], ["objekt", { code: "c.objekt.1" }]];
  for (const [ime, koda] of neveljavne) {
    u = await racun();
    r = await izbris(u, { reauth: "provider", apple_authorization_code: koda });
    assert(r.status === 200 && r.body.message === "Account deleted." && !(await obstaja(u.id)), `${ime}: 200, izbris tece naprej`, r);
    if (typeof koda === "string") negativne.push(koda);
  }
  negativne.push("c.polje.1", "c.objekt.1");
  u = await racun();
  r = await izbris(u, { reauth: "provider" });
  assert(r.status === 200, "brez polja: 200", r);
  const meja = "c." + "y".repeat(1022);   // tocno 1024 znakov: veljavno
  u = await racun();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: meja });
  assert(await pocakaj(() => klici("/auth/token", meja).length === 1, 3000), "tocno 1024 znakov: Applu gre");

  console.log("\n# (10) izbris ne uspe -> Applu nic (401 reauth_required, 409 club_has_orders, 400 brez gesla)");
  u = await racun();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.neuspeh401.1" }, PORT, oauth(3600));
  assert(r.status === 401 && r.body.error === "reauth_required" && await obstaja(u.id), "star amr: 401 reauth_required, vrstica ostane", r);
  r = await izbris(u, { apple_authorization_code: "c.neuspeh400.1" });
  assert(r.status === 400 && await obstaja(u.id), "brez gesla in reauth: 400", r);
  const klub = (await pool.query("INSERT INTO clubs (owner_user_id, name) VALUES ($1, 'Klub Apple') RETURNING id", [u.id])).rows[0].id;
  const ev = (await pool.query("INSERT INTO events (club_id, title, status, start_at, ticket_price_cents, capacity) VALUES ($1, 'D', 'published', NOW() + INTERVAL '2 days', 1000, 10) RETURNING id", [klub])).rows[0].id;
  await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email) VALUES ('OUT-AP-1', NULL, $1, $2, 1, 1000, 1000, 'pending', 'x@primer.si')`, [ev, klub]);
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.neuspeh409.1" });
  assert(r.status === 409 && r.body.error === "club_has_orders" && await obstaja(u.id), "lastnik kluba z narocili: 409 club_has_orders", r);
  negativne.push("c.neuspeh401.1", "c.neuspeh400.1", "c.neuspeh409.1");

  console.log("\n# (11) backend brez okolja / z neveljavnim kljucem: izbris 200, Applu nic");
  u = await racun(PORT_BREZ);
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.brezokolja.1" }, PORT_BREZ);
  assert(r.status === 200 && !(await obstaja(u.id)), "brez okolja: 200", r);
  u = await racun(PORT_SLAB);
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.slabkljuc.1" }, PORT_SLAB);
  assert(r.status === 200 && !(await obstaja(u.id)), "neveljaven kljuc: 200", r);
  negativne.push("c.brezokolja.1", "c.slabkljuc.1");

  console.log("\n# (12) negativni primeri: Applu ni slo nic (zadnji pozitivni klic potrjuje, da so prejsnji ze odsli)");
  u = await racun();
  r = await izbris(u, { reauth: "provider", apple_authorization_code: "c.zadnji.1" });
  assert(await pocakaj(() => klici("/auth/revoke", "c.zadnji.1").length === 1, 3000), "zadnji pozitivni primer: revoke poklican");
  const poslane = new Set(appleKlici.map((k) => k.polja.code).filter(Boolean));
  const vsiTokenKlici = appleKlici.filter((k) => k.pot === "/auth/token").map((k) => k.polja.code);
  assert(negativne.every((k) => !poslane.has(k)) && vsiTokenKlici.every((k) => /^c\.[A-Za-z0-9._-]+$/.test(k)) && !vsiTokenKlici.some((k) => /presledek|amp|polje|objekt|predolgo|neuspeh|brezokolja|slabkljuc/.test(k)),
    "nobena negativna koda ni prisla do Appla", vsiTokenKlici.filter((k) => k.length < 60));

  console.log("\n# (13) casovna meja 8 s pri visecem Applu");
  assert(await pocakaj(() => /korak=token status=casovna_meja/.test(glavni.log), Math.max(0, visiOd + 11000 - Date.now())), "dnevnik: korak=token status=casovna_meja (po ~8 s)");
  const ms = Date.now() - visiOd;
  assert(ms >= 7000, "casovna meja ni prekratka (>= 7 s)", ms);

  console.log("\n# (14) dnevnik ne vsebuje kode, zetonov, client_secret, e-naslova, sub");
  const vsiLogi = glavni.log + brez.log + slab.log;
  const secret = f.client_secret || "NI";
  assert(!/SKRIVNOST/.test(vsiLogi), "brez »SKRIVNOST« (koda, access/refresh/id_token, Applov opis, kljuc)", (vsiLogi.match(/.{0,80}SKRIVNOST.{0,40}/) || [])[0]);
  assert(!vsiLogi.includes(secret) && !vsiLogi.includes(secret.split(".")[0]), "brez client_secret");
  assert(!/c\.(visi|grant|pada|cudna|brezrefresh|revoke5xx|revoke400|geslo|zadnji)\.1/.test(vsiLogi) && !/privaterelay/.test(vsiLogi) && !/00000000-0000-4000/.test(vsiLogi),
    "brez testnih kod, e-naslova, uid", (vsiLogi.match(/.{0,80}(c\.\w+\.1|privaterelay|00000000-0000-4000).{0,20}/) || [])[0]);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (fail) console.log("\n--- log glavnega streznika ---\n" + glavni.log + "\n--- brez ---\n" + brez.log + "\n--- slab ---\n" + slab.log);
  for (const s of [glavni, brez, slab]) s.proc.kill();
  for (const v of visece) { try { v.destroy(); } catch (_) {} }
  for (const s of [stubServer, appleServer]) { s.closeAllConnections && s.closeAllConnections(); s.close(); }
  await pool.end();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
