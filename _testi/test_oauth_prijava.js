#!/usr/bin/env node
/**
 * Prijava z Googlom in Applom prek Supabase (outly-backend, 14. 11. 2026; ARCHITECTURE »Prijava z Googlom in Applom«, I35).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5446/postgres" node _testi/test_oauth_prijava.js
 *
 * Lazni »Supabase« (JWKS + GET /auth/v1/user + /auth/v1/settings) na portu 3362, backend na 3361. Oblika zetonov in odgovora /user
 * posnema GoTrue (supabase/auth, internal/api/provider/oidc.go parseGoogleIDToken/parseAppleIDToken, external.go:188-196):
 *   - Google: user_metadata { email, email_verified: true (boolean), full_name, name, picture, avatar_url, provider_id, sub, iss }
 *   - Apple:  user_metadata { email, email_verified: true (boolean; GoTrue ga postavi sam, Apple-ov niz »true« ignorira),
 *             custom_claims { is_private_email, auth_time }, iss, provider_id, sub } — BREZ imena in BREZ username
 *   - app_metadata { provider: "google" | "apple", providers: [...] }; /user: email_confirmed_at nastavljen (user.Confirm()).
 * Preverja: (1) Google in Apple uporabnik ob prvem GET /me dobi vrstico (ne 403, ne 503); (2) ime iz Googlovega full_name NE postane
 * uporabnisko ime; (3) Applov skriti naslov (@privaterelay.appleid.com) NE postane uporabnisko ime (nakljucen niz), ampak »user«
 * (pripona ob trku), uporabnik pa ime izbere prek PATCH /me; (4) povezava na obstojec racun z istim potrjenim e-naslovom;
 * (5) nepotrjen naslov se zavrne (I35 ostane: dokaz je /user, ne user_metadata).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3361, STUB_PORT = 3362;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-oauth";

const stub = { odgovori: new Map(), klici: new Map() };
const klicev = (sub) => stub.klici.get(sub) || 0;
const stubServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) {
    let sub = "?";
    try { sub = JSON.parse(Buffer.from(String(req.headers.authorization || "").split(".")[1], "base64url")).sub; } catch (_) {}
    stub.klici.set(sub, klicev(sub) + 1);
    const o = stub.odgovori.get(sub);
    if (!o) { res.statusCode = 404; return res.end("{}"); }
    return res.end(JSON.stringify(o));
  }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false, google: true, apple: true } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});

const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
function zeton(sub, email, user_metadata, app_metadata) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${STUB_PORT}/auth/v1`, aud: "authenticated", sub, email, role: "authenticated", exp: now + 3600, iat: now,
    app_metadata, user_metadata, is_anonymous: false });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
// Odgovor GET /auth/v1/user za potrjen racun (GoTrue: user.Confirm() ob OAuth s Verified=true).
const potrjen = (sub, email, provider) => ({ id: sub, email, email_confirmed_at: "2026-11-14T10:00:00Z", confirmed_at: "2026-11-14T10:00:00Z",
  app_metadata: { provider, providers: [provider] }, identities: [{ provider }] });
const nepotrjen = (sub, email) => ({ id: sub, email, email_confirmed_at: null, confirmed_at: null });

const google = (sub, email, ime, potrditev = true) => zeton(sub, email, {
  avatar_url: "https://lh3.googleusercontent.com/a/x", email, email_verified: potrditev, full_name: ime, name: ime,
  iss: "https://accounts.google.com", phone_verified: false, picture: "https://lh3.googleusercontent.com/a/x", provider_id: "108700000000000000001", sub: "108700000000000000001",
}, { provider: "google", providers: ["google"] });
const apple = (sub, email, privatni, dodatno = {}) => zeton(sub, email, {
  custom_claims: { auth_time: 1794000000, is_private_email: privatni }, email, email_verified: true,
  iss: "https://appleid.apple.com", provider_id: "001234.abcdef0123456789.1234", sub: "001234.abcdef0123456789.1234", ...dodatno,
}, { provider: "apple", providers: ["apple"] });

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { authorization: "Bearer " + token, ...(body ? { "content-type": "application/json" } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  const vrstice = async (email) => (await pool.query("SELECT id, email, username, supabase_uid, email_verified, password_hash, onboarded_at FROM users WHERE lower(email)=$1", [email])).rows;
  const stVrstic = async () => Number((await pool.query("SELECT count(*) AS n FROM users")).rows[0].n);

  await new Promise((r) => stubServer.listen(STUB_PORT, r));
  let log = "";
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${STUB_PORT}`,
    SUPABASE_PUBLISHABLE_KEY: "sb_publishable_testni_kljuc", RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }

  console.log("\n# (1) Google: nov uporabnik -> vrstica, ime NI iz full_name");
  let s = uuid(1), tok = google(s, "jnovak91@gmail.com", "Janez Novak");
  stub.odgovori.set(s, potrjen(s, "jnovak91@gmail.com", "google"));
  let r = await api("GET", "/me", tok);
  assert(r.status === 200 && r.body.email === "jnovak91@gmail.com", "GET /me -> 200 in vrstica", r);
  assert(r.body.username === "jnovak91", "uporabnisko ime = del e-naslova, NE Googlov full_name (javno ime brez izbire)", r.body.username);
  assert(r.body.onboarded_at === null || r.body.onboarded_at === undefined, "racun ni dokoncan (onboarded_at prazen) -> odjemalec pokaze dokoncanje", r.body.onboarded_at);
  let v = await vrstice("jnovak91@gmail.com");
  assert(v.length === 1 && v[0].supabase_uid === s && v[0].email_verified === true && v[0].password_hash === null, "vrstica: supabase_uid, email_verified, brez gesla", v);
  const k = klicev(s);
  r = await api("GET", "/me", tok);
  assert(r.status === 200 && klicev(s) === k, "drugi GET /me: brez novega klica na /user (vroca pot)");

  console.log("\n# (2) Apple »Hide My Email«: relay naslov NI uporabnisko ime");
  s = uuid(2); let relay = "k3x9q2v7m1@privaterelay.appleid.com";
  stub.odgovori.set(s, potrjen(s, relay, "apple"));
  r = await api("GET", "/me", apple(s, relay, true));
  assert(r.status === 200 && r.body.email === relay, "GET /me -> 200 (ne 403 email_unverified, ne 503)", r);
  assert(r.body.username === "user", "uporabnisko ime »user« (nakljucen niz iz relay naslova ni javno ime)", r.body.username);
  s = uuid(3); relay = "abc_def_123_xyz@PrivateRelay.AppleID.com";
  stub.odgovori.set(s, potrjen(s, relay.toLowerCase(), "apple"));
  r = await api("GET", "/me", apple(s, relay.toLowerCase(), "true"));
  assert(r.status === 200 && /^user_\d{4}$/.test(r.body.username), "drugi relay uporabnik: »user_NNNN« (trk imena, 23505 -> pripona)", r.body.username);

  console.log("\n# (3) Apple z deljenim pravim naslovom (is_private_email=false) -> del e-naslova kot pri Googlu");
  s = uuid(4);
  stub.odgovori.set(s, potrjen(s, "marta.k@icloud.com", "apple"));
  r = await api("GET", "/me", apple(s, "marta.k@icloud.com", false));
  assert(r.status === 200 && r.body.username === "martak", "username »martak«", r.body.username);

  console.log("\n# (4) uporabnik sam izbere ime: user_metadata.username (PUT /auth/v1/user) in PATCH /me");
  s = uuid(5); relay = "q1w2e3r4t5@privaterelay.appleid.com";
  stub.odgovori.set(s, potrjen(s, relay, "apple"));
  r = await api("GET", "/me", apple(s, relay, true, { username: "izbrano_ime" }));
  assert(r.status === 200 && r.body.username === "izbrano_ime", "user_metadata.username (ce ga odjemalec ze ima) ima prednost", r.body.username);
  const tokApple2 = apple(uuid(2), "k3x9q2v7m1@privaterelay.appleid.com", true);
  r = await api("PATCH", "/me", tokApple2, { username: "plesalec" });
  assert(r.status === 200 && r.body.username === "plesalec", "PATCH /me { username } spremeni ime Apple racuna", r);

  console.log("\n# (5) povezava na obstojec racun z istim potrjenim e-naslovom (Google na racun iz casov e-pošte+geslo)");
  await pool.query("INSERT INTO users (email, password_hash, username, email_verified) VALUES ('staro@gmail.com', 'hash', 'staro_ime', true)");
  const staroId = (await vrstice("staro@gmail.com"))[0].id, pred = await stVrstic();
  s = uuid(6);
  stub.odgovori.set(s, potrjen(s, "staro@gmail.com", "google"));
  r = await api("GET", "/me", google(s, "staro@gmail.com", "Stari Uporabnik"));
  v = await vrstice("staro@gmail.com");
  assert(r.status === 200 && r.body.id === staroId && r.body.username === "staro_ime", "isti racun, ime ostane", r.body);
  assert(v.length === 1 && v[0].supabase_uid === s && await stVrstic() === pred, "supabase_uid povezan, nobene nove vrstice", v);
  // GoTrue poveze Google identiteto na ISTEGA auth uporabnika (isti sub) -> vroca pot po uid.
  const k6 = klicev(s);
  r = await api("GET", "/me", google(s, "staro@gmail.com", "Stari Uporabnik"));
  assert(r.status === 200 && r.body.id === staroId && klicev(s) === k6, "ponovitev: isti racun po uid, brez klica na /user");

  console.log("\n# (6) I35 ostane: nepotrjen naslov -> 403, nobene vrstice");
  const pred6 = await stVrstic();
  s = uuid(7);
  r = await api("GET", "/me", google(s, "ponarejen@gmail.com", "Ponarejen", false));
  assert(r.status === 403, "user_metadata.email_verified=false -> 403 (hitri filter)", r);
  stub.odgovori.set(s, nepotrjen(s, "ponarejen@gmail.com"));
  r = await api("GET", "/me", google(s, "ponarejen@gmail.com", "Ponarejen", true));
  assert(r.status === 403, "email_verified=true v zetonu, a /user pravi nepotrjen -> 403", r);
  s = uuid(8); relay = "zrtev@outly.si";
  await pool.query("INSERT INTO users (email, password_hash, username, email_verified) VALUES ('zrtev@outly.si', 'hash', 'zrtev', true)");
  stub.odgovori.set(s, nepotrjen(s, relay));
  r = await api("GET", "/me", apple(s, relay, false));
  v = await vrstice("zrtev@outly.si");
  assert(r.status === 403 && v[0].supabase_uid === null, "Apple z naslovom tujega racuna brez potrditve pri viru: 403, vrstica ni povezana", { r, v });
  assert(await stVrstic() === pred6 + 1, "nobenih novih vrstic (samo ročno vstavljena zrtev)");

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (fail) console.log("\n--- log streznika ---\n" + log);
  srv.kill(); stubServer.closeAllConnections && stubServer.closeAllConnections(); stubServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
