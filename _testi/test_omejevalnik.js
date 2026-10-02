#!/usr/bin/env node
/**
 * Test omejevalnika poskusov v PostgreSQL (issue #24, invarianta I15). Zagon (lokalno, PG16, vse migracije):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_omejevalnik.js
 *
 * Skripta dvigne lokalni JWKS (port 3963) in vec PROCESOV backenda na isti bazi (porti 3161-3166).
 * (a) meja velja cez dva ločena procesa  - na stari kodi (stevec v pomnilniku procesa) PADE
 * (b) meja preživi restart procesa
 * (c) hkratni poskusi (Promise.all, dva procesa hkrati) ne prekoračijo meje
 * (d) okvara omejevalnika: fail-open (ogled, iskanje) / fail-closed (brisanje, prosnja); sken nima omejevalnika
 * (e) ključ ne vsebuje IP-ja ali imena poti; izvoz baze tabele ne vsebuje; čiščenje izteklih vrstic
 */
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 3963;
const IME_SEJE = "outly_test_omejevalnik";
const dbZImenom = DB + (DB.includes("?") ? "&" : "?") + "application_name=" + IME_SEJE;

// --- kljuc + JWKS ---
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-omejevalnik";
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

// En proces backenda na svojem portu; env se prepise (npr. DATABASE_URL, OMEJEVALNIK_CISCENJE_MS).
const procesi = [];
async function zazeni(port, env) {
  const srv = spawn("node", ["index.js"], {
    env: { ...process.env, PORT: String(port), DATABASE_URL: dbZImenom, SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test-omejevalnik-skrivnost-0123456789", ...(env || {}) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const p = { port, base: `http://127.0.0.1:${port}`, log: "", srv, umrl: null };
  srv.stdout.on("data", (d) => p.log += d); srv.stderr.on("data", (d) => p.log += d);
  srv.on("exit", (code, sig) => { p.umrl = { code, sig }; });
  procesi.push(p);
  for (let i = 0; i < 80 && p.umrl === null; i++) { try { await fetch(p.base + "/"); break; } catch { await spi(100); } }
  if (p.umrl !== null) throw new Error(`proces na portu ${port} je umrl ob zagonu (port zaseden?): ${p.log.slice(-300)}`);
  p.ustavi = async () => { if (p.umrl === null) { srv.kill(); for (let i = 0; i < 50 && p.umrl === null; i++) await spi(50); } };
  return p;
}
async function klic(p, method, pot, token, body) {
  const t0 = Date.now();
  const r = await fetch(p.base + pot, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const besedilo = await r.text();
  return { status: r.status, besedilo, retryAfter: r.headers.get("retry-after"), ms: Date.now() - t0 };
}
// Javna pot z mejo 5/h (kljuc "prosnja"); prazno telo -> 400 (validacija), omejevalnik steje vseh 5 poskusov.
const prosnja = (p) => klic(p, "POST", "/creator-applications", null, {});

(async () => {
  const pool = new Pool({ connectionString: DB, max: 3 });
  pool.on("error", () => {});
  await pool.query("TRUNCATE omejitve, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));

  try {
    // ------------------------------------------------------------------
    console.log("\n# (a) Meja velja cez dva ločena procesa na isti bazi");
    const A = await zazeni(3161), B = await zazeni(3162);
    const a = []; for (let i = 0; i < 3; i++) a.push((await prosnja(A)).status);
    const b = []; for (let i = 0; i < 3; i++) b.push(await prosnja(B));
    assert(a.every((s) => s === 400), "proces A: 3 poskusi -> 400 (validacija, znotraj meje)", a);
    assert(b[0].status === 400 && b[1].status === 400, "proces B: 4. in 5. poskus (skupaj z A) -> 400", b.map((x) => x.status));
    assert(b[2].status === 429, "proces B: 6. poskus (skupaj z A) -> 429", b.map((x) => x.status));
    assert(b[2].besedilo === "Too many requests. Please try again later.", "429: isto besedilo kot prej", b[2].besedilo);
    const ra = Number(b[2].retryAfter);
    assert(Number.isInteger(ra) && ra >= 3590 && ra <= 3600, "429: Retry-After je ostanek okna (~3600 s)", b[2].retryAfter);
    const a2 = await prosnja(A);
    assert(a2.status === 429, "proces A: po tem, ko je B prekoračil mejo, tudi A dobi 429", a2.status);
    const ogled = await klic(A, "POST", "/views", null, {});
    assert(ogled.status === 204, "druga pot (ogled) ima svoj števec: 204", ogled.status);

    // ------------------------------------------------------------------
    console.log("\n# (b) Meja preživi restart procesa");
    await A.ustavi(); await B.ustavi();
    const C = await zazeni(3163);
    const c = await prosnja(C);
    assert(c.status === 429, "svež proces: meja iz prejšnjih procesov še velja -> 429", c.status);

    // ------------------------------------------------------------------
    console.log("\n# (e1) Ključ v bazi ne vsebuje osebnih podatkov");
    const kljuci = (await pool.query("SELECT kljuc, stevec FROM omejitve ORDER BY kljuc")).rows;
    assert(kljuci.length === 2, "v bazi sta natanko 2 vrstici (prosnja, ogled)", kljuci);
    assert(kljuci.every((k) => /^[0-9a-f]{32}$/.test(k.kljuc)), "ključ je 32 šestnajstiških znakov", kljuci.map((k) => k.kljuc));
    assert(kljuci.every((k) => !/127|::|prosnja|ogled|\./.test(k.kljuc)), "ključ ne vsebuje IP-ja ali imena poti");
    const golSha = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 32);
    const znani = new Set(["prosnja", "ogled"].flatMap((k) => ["::ffff:127.0.0.1", "127.0.0.1", "::1"].map((ip) => golSha(`${k}:${ip}`))));
    assert(kljuci.every((k) => !znani.has(k.kljuc)), "ključ NI golo sha256(pot:IP) (HMAC s skrivnostjo: IP-ja se ne da uganiti s seznamom)");
    assert(kljuci.some((k) => k.stevec === 6) && kljuci.every((k) => k.stevec <= 6), "števec zavrnjenih poskusov je omejen na najvec+1 (7 poskusov, števec 6)", kljuci);

    // ------------------------------------------------------------------
    console.log("\n# Okno poteče -> števec se ponastavi");
    // Svež proces (brez lokalnega zapisa »blokiran do«): vrstice skrajšamo neposredno v bazi.
    await C.ustavi();
    await pool.query("UPDATE omejitve SET okno_do = now() - interval '1 second'");
    const H = await zazeni(3168);
    const po = await prosnja(H);
    assert(po.status === 400, "po izteku okna spet 400 (števec nazaj na 1)", po.status);
    const vrst = (await pool.query("SELECT stevec, okno_do > now() + interval '3590 seconds' AS novo FROM omejitve ORDER BY stevec")).rows;
    assert(vrst.some((v) => v.stevec === 1 && v.novo), "vrstica: stevec = 1, novo okno ~1 h", vrst);

    // ------------------------------------------------------------------
    console.log("\n# (c) Hkratni poskusi iz dveh procesov ne prekoračijo meje");
    await H.ustavi();
    await pool.query("TRUNCATE omejitve");
    const D = await zazeni(3164), E = await zazeni(3165);
    const vsi = await Promise.all(Array.from({ length: 40 }, (_, i) => prosnja(i % 2 ? D : E)));
    const stevilo = (s) => vsi.filter((x) => x.status === s).length;
    assert(stevilo(400) === 5, "natanko 5 od 40 hkratnih poskusov (dva procesa) gre skozi", { "400": stevilo(400), "429": stevilo(429) });
    assert(stevilo(429) === 35, "ostalih 35 -> 429", { "429": stevilo(429) });
    const st = (await pool.query("SELECT stevec FROM omejitve")).rows;
    assert(st.length === 1 && st[0].stevec === 6, "v bazi ena vrstica, števec = najvec + 1 (6)", st);

    // ------------------------------------------------------------------
    console.log("\n# (d) Okvara omejevalnika: fail-open / fail-closed po poti");
    const T = zeton("brisalec@outly.si", uuid(1));
    const me = await klic(D, "GET", "/me", T);
    assert(me.status === 200, "GET /me ustvari uporabnika", me.besedilo);
    const brez = await klic(D, "DELETE", "/me", T, {});
    assert(brez.status === 400, "brez okvare: DELETE /me pride do poti (400 »Password required«)", { s: brez.status, b: brez.besedilo });

    // d1: omejevalnik se obesi (druga seja drži ACCESS EXCLUSIVE ključavnico) -> časovna omejitev poizvedbe
    const drzi = await pool.connect();
    await drzi.query("BEGIN");
    await drzi.query("LOCK TABLE omejitve IN ACCESS EXCLUSIVE MODE");
    try {
      const ogledOk = await klic(D, "POST", "/views", null, {});
      assert(ogledOk.status === 204 && ogledOk.ms < 5000, "obešen omejevalnik, pot »ogled« (fail-open): 204 v < 5 s", { s: ogledOk.status, ms: ogledOk.ms });
      const iskanje = await klic(D, "GET", "/users/search?q=bri", T);
      assert(iskanje.status === 200 && iskanje.ms < 5000, "obešen omejevalnik, pot »iskanje« (fail-open): 200", { s: iskanje.status, ms: iskanje.ms });
      const brisi = await klic(D, "DELETE", "/me", T, {});
      assert(brisi.status === 503 && brisi.ms < 5000, "obešen omejevalnik, pot »brisanje« (fail-closed): 503 v < 5 s, ne 400/200", { s: brisi.status, ms: brisi.ms, b: brisi.besedilo });
      assert(Number(brisi.retryAfter) > 0, "503 ima Retry-After", brisi.retryAfter);
      const prenos = await klic(D, "POST", "/tickets/1/transfer", T, {});
      assert(prenos.status === 503, "obešen omejevalnik, pot »prenos« (fail-closed): 503", prenos.status);
      const prs = await prosnja(D);
      assert(prs.status === 429, "že blokiran ključ (zapomnjen v procesu) ostane 429 tudi ob okvari omejevalnika", prs.status);
      const uporabnik = await pool.query("SELECT 1 FROM users WHERE email='brisalec@outly.si'");
      assert(uporabnik.rowCount === 1, "uporabnik ob 503 NI izbrisan");
      // sken nima omejevalnika, zato obešen omejevalnik nanj ne vpliva (pot zahteva žeton -> 401, ne 503)
      const sken = await klic(D, "POST", "/business/tickets/scan", null, {});
      assert(sken.status === 401 && sken.ms < 1000, "sken: omejevalnik ni na poti (401 takoj, ne 503/počasen)", { s: sken.status, ms: sken.ms });
    } finally {
      await drzi.query("ROLLBACK"); drzi.release();
    }
    const spet = await klic(D, "DELETE", "/me", T, {});
    assert(spet.status === 400, "po koncu okvare omejevalnik spet dela brez restarta (400)", spet.status);

    // d2: tabela ne obstaja (napaka poizvedbe, ne časovna omejitev)
    await pool.query("ALTER TABLE omejitve RENAME TO omejitve_zacasno");
    try {
      const o2 = await klic(D, "POST", "/views", null, {});
      const b2 = await klic(D, "DELETE", "/me", T, {});
      assert(o2.status === 204 && o2.ms < 1500, "manjkajoča tabela: ogled (fail-open) 204 hitro", { s: o2.status, ms: o2.ms });
      assert(b2.status === 503 && b2.ms < 1500, "manjkajoča tabela: brisanje (fail-closed) 503 hitro", { s: b2.status, ms: b2.ms });
      assert(D.umrl === null, "proces živi");
      assert(/\[omejevalnik\]/.test(D.log), "napaka je zapisana v dnevnik (ni tiha)");
    } finally {
      await pool.query("ALTER TABLE omejitve_zacasno RENAME TO omejitve");
    }

    // d3: baza prekine povezave omejevalnika (kot test_pool_napaka)
    const pids = (await pool.query("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND pid <> pg_backend_pid()", [IME_SEJE])).rows.map((r) => r.pid);
    assert(pids.length >= 2, "procesa D in E imata odprte povezave", pids.length);
    for (const pid of pids) await pool.query("SELECT pg_terminate_backend($1)", [pid]);
    await spi(700);
    const po3 = await klic(D, "DELETE", "/me", T, {});
    assert(po3.status === 400, "po prekinitvi povezav omejevalnik odpre nove (400, ne 503)", { s: po3.status, log: D.log.slice(-300) });

    // d4: baza popolnoma nedosegljiva
    const F = await zazeni(3166, { DATABASE_URL: "postgres://postgres:postgres@localhost:1/outly" });
    const f1 = await klic(F, "POST", "/views", null, {});
    assert(f1.status === 204 && f1.ms < 5000, "nedosegljiva baza: ogled (fail-open) 204, brez čakanja na 10 s", { s: f1.status, ms: f1.ms });
    const f2 = await prosnja(F);
    assert(f2.status === 503 && f2.ms < 5000, "nedosegljiva baza: prosnja (fail-closed) 503", { s: f2.status, ms: f2.ms });
    assert(F.umrl === null, "proces živi (brez »Unhandled 'error'«)", F.log.slice(-300));
    assert(!/Unhandled 'error'/.test(F.log), "brez »Unhandled 'error' event« v dnevniku");

    // d5: sken ni na omejevalniku (statična preverba izvorne kode)
    const koda = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8");
    const skenPoti = koda.split("\n").filter((v) => /^app\.(get|post|put|patch|delete)\(\s*"\/business\/(tickets\/scan|tickets\/scan-batch|scan-key|events\/:id\/scan-list)"/.test(v));
    assert(skenPoti.length >= 4, "najdene vse 4 skenerske poti", skenPoti.length);
    assert(skenPoti.every((v) => !/omeji\(/.test(v)), "nobena skenerska pot nima omeji()", skenPoti.filter((v) => /omeji\(/.test(v)));
    await F.ustavi();

    // ------------------------------------------------------------------
    console.log("\n# (e2) Izvoz baze ne vsebuje tabele omejitev");
    await pool.query("UPDATE users SET role='admin' WHERE email='brisalec@outly.si'");
    const rizvoz = await fetch(D.base + "/admin/api/export", { headers: { authorization: "Bearer " + T } });
    const izvoz = JSON.parse(await rizvoz.text());
    assert(rizvoz.status === 200 && izvoz.tables && izvoz.tables.users, "izvoz -> 200", rizvoz.status);
    assert(!("omejitve" in izvoz.tables), "izvoz NE vsebuje tabele omejitve (kratkotrajen števec, hashi IP-jev)", Object.keys(izvoz.tables));

    // ------------------------------------------------------------------
    console.log("\n# (e3) Čiščenje izteklih vrstic");
    await D.ustavi(); await E.ustavi();
    await pool.query("TRUNCATE omejitve");
    await pool.query("INSERT INTO omejitve (kljuc, okno_do, stevec) VALUES ('izteklo', now() - interval '5 minutes', 3), ('aktivno', now() + interval '30 minutes', 2)");
    const G = await zazeni(3167, { OMEJEVALNIK_CISCENJE_MS: "300" });
    await spi(1500);
    const ostalo = (await pool.query("SELECT kljuc FROM omejitve ORDER BY kljuc")).rows.map((r) => r.kljuc);
    assert(ostalo.length === 1 && ostalo[0] === "aktivno", "iztekla vrstica pobrisana, aktivna ostane", ostalo);
    await G.ustavi();
  } finally {
    for (const p of procesi) { try { p.srv.kill(); } catch (_) {} }
    jwksServer.close();
    await pool.end().catch(() => {});
  }

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
