#!/usr/bin/env node
/**
 * Nujni nacin agenta (#330, 3. del; migracija 060; agent_predlogi.js; ARCHITECTURE »Dostop za agenta«, invarianta I58). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_agent_nujno.js
 * Lokalni JWKS 6160, lazni Resend 6169; strezniki: A 6161 (nujni nacin vklopljen), OFF 6162 (AGENT_NUJNO=0), BREZ 6163 (brez AGENT_NUJNO_MAIL),
 * BREZR 6164 (brez Resenda), H1-H3 6165-6167 (za 4 hkratne klice iz 4 procesov: semafor agenta je na proces).
 *
 *  1. obseg: `nujno` samo z `beri` + `predlagaj` (panel 400, CHECK v bazi zavrne tudi rocni SQL); zeton brez `nujno` -> 403.
 *  2. stikalo in prejemnik: AGENT_NUJNO=0 -> 503 nujno_off BREZ baze (tudi ob zaklenjeni agent_zetoni); brez AGENT_NUJNO_MAIL ali Resenda -> 503 nujno_brez_obvestila (fail-closed).
 *  3. telo: brez citata / prekratek / predolg / kontrolni znaki -> 400; seja ni povezava claude.ai -> 400; tuj predlog -> 404.
 *  4. star predlog (> 1 h) 409 predlog_prestar (ostane caka); zastarel 409 (nic se ne spremeni); zeton preklican med cakanjem na zaklep -> 409 zeton_neveljaven.
 *  5. izvedba: ISTA pot kot potrditev admina (ustavitev prodaje -> I53 preklic cakajocega narocila), admin_dejanja z oznako nujno, citatom, sejo, brez admina;
 *     predlog potrjen z nujno_*; odgovor agentu brez osebnih podatkov; drugi klic 409 (enkratnost).
 *  6. izkljucena dejanja (izvoz baze, vloga admin/backup): 403 nujno_izkljuceno, tudi ce bi bila v bazi in na belem seznamu (simulacija: CHECK odstranjen, vrstica vstavljena).
 *  7. mail Martinu: natanko enkrat; napaka PO sprejemu (prekinjena povezava) -> brez ponovitve + POZOR; dokazana zavrnitev (422) -> ponovitev, en mail; brez podatkov kupcev.
 *  8. meja 3 na 24 h GLOBALNO: 4. -> 429 (tudi z drugim zetonom), 4 hkratni klici iz 4 procesov -> natanko 3 izvedbe in 3 maili; drsno okno.
 *  9. panel: GET /admin/api/predlogi/nujno (rdec pas), POST .../nujno-pregledano (admin_dejanja), ne-admin in zeton agenta 403; summary.nujno_nepregledanih.
 * 10. sken nedotaknjen: nujna pot ne uporablja skenPool; mail se poslje samo iz agent_predlogi.js.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");
const pg = require("pg");
pg.types.setTypeParser(20, (v) => (v === null ? null : parseInt(v, 10)));
const { Pool } = pg;

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 6160, PORT = 6161, PORT_OFF = 6162, PORT_BREZ = 6163, PORT_BREZR = 6164, PORTI_H = [6165, 6166, 6167], RESEND_PORT = 6169;
const MARTIN = "nujno-martin@outly.test";
const SEJA = "https://claude.ai/code/session_01TestNujnoNacin";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-nujno";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});
function b64u(o) { return Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url"); }
function jwt(email, sub) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${JWKS_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now,
    user_metadata: { email_verified: true, username: email.split("@")[0].replace(/[^a-z0-9_]/gi, "") } });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

// Lazni Resend (kot test_racun_kupcu.js): R.napaka = zavrnitev PRED obdelavo (422, dokazana), R.rezim = napaka PO sprejemu maila (kot jo vidi Resend SDK 3.x)
const R = { poslano: [], napaka: 0, rezim: [] };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", (x) => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      if (R.napaka > 0) { R.napaka--; res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub: zavrnjeno", statusCode: 422 })); }
      const m = JSON.parse(d);
      R.poslano.push(m);
      const rz = R.rezim.shift();
      if (rz === "reset") return req.socket.destroy();   // mail SPREJET, povezava prekinjena
      if (rz === "json500") { res.writeHead(500, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "internal_server_error", message: "stub", statusCode: 500 })); }
      if (rz === "zamik") return setTimeout(() => { try { res.writeHead(200, { "content-type": "application/json" }); res.end('{"id":"pozno"}'); } catch (_) { /* odjemalec je odnehal */ } }, 2500);   // rok odjemalca
      res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + R.poslano.length }));
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const mailiZa = (id) => R.poslano.filter((m) => String(m.subject || "").includes(`#${id}:`));
const mailiMartinu = () => R.poslano.filter((m) => (Array.isArray(m.to) ? m.to : [m.to]).includes(MARTIN));

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 700) : ""); } }
const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms));
async function cakaj(pogoj, ms = 8000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(100); } return false; }
async function api(port, metoda, pot, token, telo, rok = 15000) {
  const glave = {};
  if (token) glave.authorization = "Bearer " + token;
  if (telo !== undefined) glave["content-type"] = "application/json";
  const t0 = Date.now();
  const r = await fetch(`http://127.0.0.1:${port}${pot}`, { method: metoda, headers: glave, body: telo === undefined ? undefined : JSON.stringify(telo), signal: AbortSignal.timeout(rok) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t, ms: Date.now() - t0 };
}
const SKUPNO = { AGENT_API_NA_URO: "100000", AGENT_API_IP_NA_MIN: "100000", AGENT_PREDLOGI_NA_URO: "100000", AGENT_PREDLOGI_CAKA_NAJVEC: "1000", PAVZA_KMALU_MS: "0", PAVZA_PONOVNO_MS: "0",
  RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", GOST_POSTA_TIMEOUT_MS: "800",
  AGENT_NUJNO_MAIL: MARTIN, AGENT_NUJNO_MAIL_PONOVI_MS: "300", AGENT_NUJNO_MAIL_PREMOR_MS: "200", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" };
function zazeni(port, okolje) {
  const proc = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test",
    STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "", AGENT_NUJNO: "", ...SKUPNO, ...okolje }, stdio: ["ignore", "pipe", "pipe"], cwd: path.join(__dirname, "..") });
  const o = { proc, log: "", port };
  proc.stdout.on("data", (d) => o.log += d); proc.stderr.on("data", (d) => o.log += d);
  return o;
}
async function cakajStreznik(port) { for (let i = 0; i < 150; i++) { try { await fetch(`http://127.0.0.1:${port}/`); return true; } catch { await pocakaj(100); } } return false; }
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
function nicOsebnega(ime, tekst) {
  const najdeno = ["@", "kupec-nujno", "primer.si", "klub-nujno.si", "outly_agent_"].filter((n) => tekst.includes(n));
  assert(najdeno.length === 0, `${ime}: brez osebnih podatkov (e-naslovi, zeton)`, najdeno);
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE agent_zetoni, admin_dejanja, omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  await new Promise((r) => resendServer.listen(RESEND_PORT, r));
  const A = zazeni(PORT, {});
  const OFF = zazeni(PORT_OFF, { AGENT_NUJNO: "0" });
  const BREZ = zazeni(PORT_BREZ, { AGENT_NUJNO_MAIL: "" });
  const BREZR = zazeni(PORT_BREZR, { RESEND_API_KEY: "" });
  const H = PORTI_H.map((p, i) => zazeni(p, i === 0 ? { AGENT_NUJNO_NA_24H: "5" } : {}));   // H1: okolje NE more dvigniti Martinove meje 3
  const vsi = () => [A, OFF, BREZ, BREZR, ...H];
  for (const s of vsi()) assert(await cakajStreznik(s.port), `streznik ${s.port} tece`);

  try {
    const T = { admin: jwt("admin@outly.si", uuid(1)), poslovni: jwt("lastnik@outly.si", uuid(2)), kupec: jwt("kupec-nujno@primer.si", uuid(3)) };
    for (const k of Object.keys(T)) { const r = await api(PORT, "GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    const adminId = (await pool.query("SELECT id FROM users WHERE email='admin@outly.si'")).rows[0].id;
    const lastnikId = (await pool.query("SELECT id FROM users WHERE email='lastnik@outly.si'")).rows[0].id;
    const kupecId = (await pool.query("SELECT id FROM users WHERE email='kupec-nujno@primer.si'")).rows[0].id;

    const K1 = (await pool.query("INSERT INTO clubs (owner_user_id, name, contact_email) VALUES ($1, 'Klub Nujno', 'info@klub-nujno.si') RETURNING id", [lastnikId])).rows[0].id;
    const dogodek = async (naslov) => (await pool.query(
      `INSERT INTO events (club_id, title, status, start_at, end_at, ticket_price_cents, capacity, poster_url, description, genres)
       VALUES ($1, $2, 'published', NOW() + INTERVAL '3 days', NOW() + INTERVAL '3 days 6 hours', 1500, 100, 'https://x.test/p.jpg', 'Rezervacije: info@klub-nujno.si', ARRAY['techno']) RETURNING id`,
      [K1, naslov])).rows[0].id;
    const E = {};
    for (const k of ["a", "b", "c", "pavza", "m1", "m2", "meja", "h1", "h2", "h3", "h4", "drsno", "izkl", "sk", "zv", "n2a", "n2b", "mail"]) E[k] = await dogodek("Dogodek " + k);
    const cakajNa = async (fn, rokMs = 5000) => { const konec = Date.now() + rokMs; for (;;) { if (await fn()) return true; if (Date.now() > konec) return false; await pocakaj(20); } };
    // seja (proces streznika) caka na zaklep: pogoj namesto fiksnega cakanja (S3)
    const nekdoCakaZaklep = (n = 1) => cakajNa(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'")).rows[0].n >= n);
    const vrstica = async (id) => (await pool.query("SELECT * FROM events WHERE id = $1", [id])).rows[0];
    const predlogVBazi = async (id) => (await pool.query("SELECT * FROM predlogi_dejanj WHERE id = $1", [id])).rows[0];
    // cakajoce narocilo na dogodku `pavza` (I53: ustavitev prodaje ga preklice); kupcev e-naslov ne sme priti ne v odgovor ne v mail
    const nar = (await pool.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, buyer_email)
       VALUES ('OUT-NUJNO1', $1, $2, $3, 1, 1500, 1500, 'EUR', 150, 'pending', 'kupec-nujno@primer.si') RETURNING id`, [kupecId, E.pavza, K1])).rows[0].id;

    // ---------------- 1. obseg ----------------
    console.log("\n# 1. obseg `nujno`");
    let r = await api(PORT, "POST", "/admin/api/agent-zetoni", T.admin, { ime: "Nujno", obseg: ["beri", "predlagaj", "nujno"], reason: "preizkus" });
    assert(r.status === 201 && JSON.stringify(r.body.obseg) === '["beri","predlagaj","nujno"]', "zeton beri + predlagaj + nujno -> 201", [r.status, r.body.obseg]);
    const NUJNO = r.body.zeton, NUJNO_ID = r.body.id;
    r = await api(PORT, "POST", "/admin/api/agent-zetoni", T.admin, { ime: "Nujno 2", obseg: ["beri", "predlagaj", "nujno"], reason: "preizkus" });
    const NUJNO2 = r.body.zeton;
    r = await api(PORT, "POST", "/admin/api/agent-zetoni", T.admin, { ime: "Nujno R", obseg: ["beri", "predlagaj", "nujno"], reason: "preizkus" });
    const NUJNO_R = r.body.zeton, NUJNO_R_ID = r.body.id;
    r = await api(PORT, "POST", "/admin/api/agent-zetoni", T.admin, { ime: "Predlogi", obseg: ["beri", "predlagaj"], reason: "preizkus" });
    const PRED = r.body.zeton;
    for (const obseg of [["beri", "nujno"], ["nujno"], ["predlagaj", "nujno"], ["beri", "predlagaj", "nujno", "nujno"]]) {
      const x = await api(PORT, "POST", "/admin/api/agent-zetoni", T.admin, { ime: "x", obseg });
      assert(x.status === 400 && x.body.error === "invalid_scope", `obseg ${JSON.stringify(obseg)} -> 400 invalid_scope`, [x.status, x.body]);
    }
    for (const [obseg, dovoljen] of [["{beri,nujno}", false], ["{nujno}", false], ["{predlagaj,nujno}", false], ["{beri,predlagaj,nujno}", true], ["{beri,predlagaj,vse}", false]]) {
      let napaka = null;
      try { await pool.query("INSERT INTO agent_zetoni (ime, zeton_sha256, obseg, velja_do) VALUES ('x', $1, $2::text[], NOW() + INTERVAL '1 day')", [sha("chk" + obseg), obseg]); } catch (e) { napaka = e; }
      assert(dovoljen ? napaka === null : (napaka && napaka.code === "23514"), `CHECK agent_zetoni_obseg_chk: ${obseg} ${dovoljen ? "dovoljen" : "zavrnjen"} (rocni SQL)`, napaka && napaka.message);
    }
    r = await api(PORT, "GET", "/admin/api/agent-zetoni", T.admin);
    assert(r.status === 200 && r.body.agent_nujno === "vklopljen", "GET agent-zetoni: agent_nujno = vklopljen", r.body.agent_nujno);
    r = await api(PORT_BREZ, "GET", "/admin/api/agent-zetoni", T.admin);
    assert(r.status === 200 && r.body.agent_nujno === "nujno_brez_obvestila", "GET agent-zetoni brez prejemnika: agent_nujno = nujno_brez_obvestila", r.body.agent_nujno);

    const predlagaj = (telo, token = NUJNO) => api(PORT, "POST", "/agent/api/predlogi", token, telo);
    const PAVZA = (id) => ({ dejanje: "event.ustavi_prodajo", cilj: { tip: "event", id }, razlog: "Napacna cena v prodaji, ustavi." });
    const NASLOV = (id, title) => ({ dejanje: "event.uredi", cilj: { tip: "event", id }, spremembe: { title }, razlog: "Popravek naslova." });
    const nov = async (telo, token = NUJNO) => { const x = await predlagaj(telo, token); if (x.status !== 201) throw new Error("predlog ni nastal: " + JSON.stringify(x.body)); return x.body.predlog.id; };
    const POTRDI = "potrjujem: ustavi prodajo Dogodek pavza";
    const izvedi = (id, telo = { potrditev: POTRDI, seja: SEJA }, token = NUJNO, port = PORT) => api(port, "POST", `/agent/api/predlogi/${id}/izvedi-nujno`, token, telo);

    const P_PRED = await nov(PAVZA(E.a), PRED);
    r = await izvedi(P_PRED, undefined, PRED);
    assert(r.status === 403 && r.body.error === "insufficient_scope", "zeton brez obsega nujno -> 403 insufficient_scope", [r.status, r.body]);

    // ---------------- 2. stikalo in prejemnik ----------------
    console.log("\n# 2. AGENT_NUJNO=0, brez prejemnika, brez Resenda");
    const P_A = await nov(PAVZA(E.a));
    r = await izvedi(P_A, undefined, NUJNO, PORT_OFF);
    assert(r.status === 503 && r.body.error === "nujno_off", "AGENT_NUJNO=0 -> 503 nujno_off", [r.status, r.body]);
    {
      const k = new pg.Client({ connectionString: DB }); await k.connect();
      await k.query("BEGIN"); await k.query("LOCK TABLE agent_zetoni, omejitve IN ACCESS EXCLUSIVE MODE");
      const x = await izvedi(P_A, undefined, NUJNO, PORT_OFF, 5000);
      await k.query("ROLLBACK"); await k.end();
      assert(x.status === 503 && x.body.error === "nujno_off" && x.ms < 2000, "AGENT_NUJNO=0 -> 503 tudi ob zaklenjenih agent_zetoni/omejitve (brez baze)", [x.status, x.ms]);
    }
    r = await api(PORT_OFF, "GET", "/agent/api/predlogi", NUJNO);
    assert(r.status === 200, "AGENT_NUJNO=0 ne izklopi branja in predlogov", r.status);
    r = await izvedi(P_A, undefined, NUJNO, PORT_BREZ);
    assert(r.status === 503 && r.body.error === "nujno_brez_obvestila", "brez AGENT_NUJNO_MAIL -> 503 nujno_brez_obvestila (fail-closed)", [r.status, r.body]);
    r = await izvedi(P_A, undefined, NUJNO, PORT_BREZR);
    assert(r.status === 503 && r.body.error === "nujno_brez_obvestila", "brez Resenda -> 503 nujno_brez_obvestila", [r.status, r.body]);
    assert((await predlogVBazi(P_A)).stanje === "caka" && (await vrstica(E.a)).sales_paused === false, "po 503 se nic ni spremenilo, predlog caka");

    // ---------------- 3. telo ----------------
    console.log("\n# 3. citat in seja");
    const slabo = [
      [{ seja: SEJA }, "invalid_potrditev"], [{ potrditev: "", seja: SEJA }, "invalid_potrditev"], [{ potrditev: "da", seja: SEJA }, "invalid_potrditev"],
      [{ potrditev: "   ", seja: SEJA }, "invalid_potrditev"], [{ potrditev: 12345, seja: SEJA }, "invalid_potrditev"], [{ potrditev: "x".repeat(1001), seja: SEJA }, "invalid_potrditev"],
      [{ potrditev: "potrjujem\u0000skrito", seja: SEJA }, "invalid_potrditev"],
      [{ potrditev: "potrjujem: ustavi \u202Eodajo", seja: SEJA }, "invalid_potrditev"], [{ potrditev: "potrjujem\u200B: ustavi prodajo", seja: SEJA }, "invalid_potrditev"],
      [{ potrditev: "potrjujem\u2066 ustavi\u2069", seja: SEJA }, "invalid_potrditev"], [{ potrditev: "\u00AD\u00AD\u00ADpotrjujem", seja: SEJA }, "invalid_potrditev"],
      [{ potrditev: "😀".repeat(1001), seja: SEJA }, "invalid_potrditev"],
      [{ potrditev: POTRDI }, "invalid_seja"], [{ potrditev: POTRDI, seja: "seja 5" }, "invalid_seja"], [{ potrditev: POTRDI, seja: "http://claude.ai/code/x" }, "invalid_seja"],
      [{ potrditev: POTRDI, seja: "https://evil.example/claude.ai/" }, "invalid_seja"], [{ potrditev: POTRDI, seja: "https://claude.ai/" + "x".repeat(600) }, "invalid_seja"],
    ];
    for (const [telo, koda] of slabo) {
      const x = await izvedi(P_A, telo);
      assert(x.status === 400 && x.body.error === koda, `${JSON.stringify(telo).slice(0, 60)} -> 400 ${koda}`, [x.status, x.body]);
    }
    r = await izvedi("abc");
    assert(r.status === 400 && r.body.error === "invalid_id", "neveljaven id -> 400", [r.status, r.body]);
    r = await izvedi(P_A, undefined, NUJNO2);
    assert(r.status === 404, "tuj predlog (drug zeton) -> 404", [r.status, r.body]);
    r = await izvedi(999999);
    assert(r.status === 404, "neobstojec predlog -> 404", r.status);
    r = await api(PORT, "PUT", `/agent/api/predlogi/${P_A}/izvedi-nujno`, NUJNO, {});
    assert(r.status === 405, "PUT izvedi-nujno -> 405", r.status);
    assert((await predlogVBazi(P_A)).stanje === "caka" && (await vrstica(E.a)).sales_paused === false, "po 400/404 se nic ni spremenilo");

    // ---------------- 4. starost, zastarelost, preklic ----------------
    console.log("\n# 4. star (> 1 h), zastarel, zeton preklican");
    await pool.query("UPDATE predlogi_dejanj SET ustvarjen_at = NOW() - INTERVAL '61 minutes' WHERE id = $1", [P_A]);
    r = await izvedi(P_A);
    assert(r.status === 409 && r.body.error === "predlog_prestar", "predlog star 61 min -> 409 predlog_prestar", [r.status, r.body]);
    assert((await predlogVBazi(P_A)).stanje === "caka" && (await vrstica(E.a)).sales_paused === false, "star predlog: nic se ne izvede, predlog ostane caka (Martin ga lahko potrdi v panelu)");
    r = await izvedi(P_A, { potrditev: "😀".repeat(1000), seja: SEJA });
    assert(r.status === 409 && r.body.error === "predlog_prestar", "N1: citat 1000 emojijev (2000 enot UTF-16) prestane validacijo dolzine (steje znake kot CHECK)", [r.status, r.body]);
    await pool.query("UPDATE predlogi_dejanj SET ustvarjen_at = NOW() - INTERVAL '59 minutes' WHERE id = $1", [P_A]);   // se veljaven (uporabljen spodaj pri meji)

    const P_Z = await nov(NASLOV(E.b, "Dogodek b (agent)"));
    await pool.query("UPDATE events SET title = 'Dogodek b (Martin)' WHERE id = $1", [E.b]);
    r = await izvedi(P_Z, { potrditev: "potrjujem: preimenuj Dogodek b", seja: SEJA });
    assert(r.status === 409 && r.body.error === "predlog_zastarel", "cilj se je spremenil -> 409 predlog_zastarel", [r.status, r.body]);
    assert((await vrstica(E.b)).title === "Dogodek b (Martin)" && (await predlogVBazi(P_Z)).stanje === "neuspel" && (await predlogVBazi(P_Z)).nujno_at === null, "zastarel: nic se ne spremeni, predlog neuspel, brez nujno_at");

    const P_R = await nov(NASLOV(E.c, "Dogodek c (agent)"), NUJNO_R);
    {
      const k = new pg.Client({ connectionString: DB }); await k.connect();
      await k.query("BEGIN"); await k.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [E.c]);
      const obljuba = izvedi(P_R, { potrditev: "potrjujem: preimenuj Dogodek c", seja: SEJA }, NUJNO_R);
      assert(await nekdoCakaZaklep(), "nujni klic caka na zaklep vrstice dogodka (pg_stat_activity)");
      const pr = await api(PORT, "POST", `/admin/api/agent-zetoni/${NUJNO_R_ID}/preklici`, T.admin, { reason: "preizkus" });
      await k.query("ROLLBACK"); await k.end();
      const x = await obljuba;
      assert(pr.status === 200 && x.status === 409 && x.body.error === "zeton_neveljaven", "zeton preklican med cakanjem na zaklep dogodka -> 409 zeton_neveljaven (preverba pod zaklepom)", [pr.status, x.status, x.body]);
      assert((await vrstica(E.c)).title === "Dogodek c", "preklican zeton: dogodek nespremenjen");
      r = await izvedi(P_R, { potrditev: "potrjujem: preimenuj Dogodek c", seja: SEJA }, NUJNO_R);
      assert(r.status === 401, "preklican zeton nato -> 401", r.status);
    }

    // ---------------- 5. izvedba ----------------
    console.log("\n# 5. izvedba po isti poti kot potrditev admina");
    const P_OK = await nov(PAVZA(E.pavza));
    R.poslano.length = 0;
    r = await izvedi(P_OK, { potrditev: POTRDI + "\r\n(Martin)", seja: SEJA });
    assert(r.status === 200 && r.body.izvedeno === true && r.body.predlog.stanje === "potrjen" && r.body.predlog.nujno_at, "izvedi-nujno -> 200, predlog potrjen", [r.status, r.body]);
    nicOsebnega("odgovor izvedi-nujno", r.text);
    assert(!("description" in (r.body.predlog || {})) && !r.text.includes("Rezervacije"), "agent ne dobi vrstice dogodka (opis = tuj vnos)", r.text.slice(0, 300));
    assert((await vrstica(E.pavza)).sales_paused === true, "prodaja ustavljena (ista pot kot PATCH /events/:id)");
    assert((await pool.query("SELECT status FROM orders WHERE id = $1", [nar])).rows[0].status === "cancelled", "I53: cakajoce narocilo preklicano v isti transakciji (ista pot)");
    const pOk = await predlogVBazi(P_OK);
    assert(pOk.stanje === "potrjen" && pOk.odlocil_admin_id === null && pOk.nujno_potrditev === POTRDI + "\n(Martin)" && pOk.nujno_seja === SEJA && pOk.nujno_at && pOk.nujno_pregledano_at === null,
      "predlog: nujno_potrditev (dobesedno, CRLF -> LF), nujno_seja, nujno_at, brez admina, nepregledan", pOk);
    const ad = (await pool.query("SELECT * FROM admin_dejanja WHERE predlog_id = $1 ORDER BY id", [P_OK])).rows;
    const dej = ad.find((x) => x.dejanje === "event.sales_pause");
    assert(dej && dej.nujno === true && dej.admin_user_id === null && dej.agent_zeton_id === NUJNO_ID && dej.cilj_id === String(E.pavza) && dej.razlog.includes(POTRDI) && dej.razlog.includes(SEJA),
      "admin_dejanja event.sales_pause: nujno, brez admina, agent_zeton_id, citat in seja v razlogu", dej);
    const sl = ad.find((x) => x.dejanje === "agent.predlog_nujno");
    assert(sl && sl.nujno === true && sl.admin_user_id === null && sl.potem.stanje === "potrjen" && sl.potem.nujno === true && sl.razlog.includes(POTRDI), "admin_dejanja agent.predlog_nujno (sled)", sl);
    assert(!ad.some((x) => x.dejanje === "agent.predlog_potrjen"), "ni zapisa »potrdil admin«");
    r = await izvedi(P_OK);
    assert(r.status === 409 && r.body.error === "predlog_ne_caka", "drugi klic -> 409 predlog_ne_caka (enkratnost)", [r.status, r.body]);
    r = await api(PORT, "POST", `/admin/api/predlogi/${P_OK}/potrdi`, T.admin, {});
    assert(r.status === 409, "admin potrdi ze izvedenega -> 409", r.status);
    // mail
    assert(await cakaj(() => mailiMartinu().length >= 1, 5000), "mail Martinu prispe takoj");
    await pocakaj(1200);   // pospravljalec (300 ms) ga ne sme poslati se enkrat
    const m1 = mailiMartinu();
    assert(m1.length === 1, "natanko en mail Martinu", m1.length);
    const mt = m1[0] ? m1[0].text + "\n" + m1[0].html + "\n" + m1[0].subject : "";
    assert(/nujno dejanje/i.test(m1[0] && m1[0].subject) && mt.includes("Ustavi prodajo") && mt.includes(POTRDI) && mt.includes(SEJA) && mt.includes("sales_paused") && mt.includes("Dogodek pavza"),
      "mail: kaj, prej → potem, citat, seja, cilj", mt.slice(0, 600));
    assert(!mt.includes("kupec-nujno") && !mt.includes("outly_agent_"), "mail brez podatkov kupcev in brez zetona");
    assert((await predlogVBazi(P_OK)).nujno_mail_poslano_at !== null, "nujno_mail_poslano_at zapisan");

    // ---------------- 6. izkljucena dejanja ----------------
    console.log("\n# 6. izvoz baze in vloga admin/backup: nikoli (tudi ce bi bila na belem seznamu)");
    const chk = (await pool.query("SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conname = 'predlogi_dejanj_dejanje_check'")).rows[0].d;
    await pool.query("ALTER TABLE predlogi_dejanj DROP CONSTRAINT predlogi_dejanj_dejanje_check");   // simulacija: dejanje je »na belem seznamu« v bazi
    const vstavi = async (dejanje, spremembe) => (await pool.query(
      "INSERT INTO predlogi_dejanj (agent_zeton_id, dejanje, cilj_tip, cilj_id, spremembe, razlog) VALUES ($1, $2, 'event', $3, $4::jsonb, 'simulacija') RETURNING id",
      [NUJNO_ID, dejanje, E.izkl, JSON.stringify(spremembe)])).rows[0].id;
    const izkl = [["db.export", {}], ["admin.export", {}], ["izvoz", {}], ["user.role", { role: "admin" }], ["user.role", { role: " Backup " }], ["uporabnik.vloga", { vloga: "admin" }],
      ["event.uredi", { nested: { role: "admin" } }]];
    try {
      for (const [d, s] of izkl) {
        const id = await vstavi(d, s);
        const x = await izvedi(id, { potrditev: "potrjujem: " + d, seja: SEJA });
        assert(x.status === 403 && x.body.error === "nujno_izkljuceno", `${d} ${JSON.stringify(s)} -> 403 nujno_izkljuceno`, [x.status, x.body]);
        assert((await predlogVBazi(id)).stanje === "caka", `${d}: nic se ne izvede`);
      }
      const idM = await vstavi("user.role", { role: "manager" });
      r = await izvedi(idM, { potrditev: "potrjujem: vloga manager", seja: SEJA });
      assert(r.status === 400 && r.body.error === "dejanje_ni_dovoljeno", "user.role manager (ni izkljucen, ni na belem seznamu kode) -> 400 dejanje_ni_dovoljeno", [r.status, r.body]);
      assert(A.log.includes("[agent-nujno] POZOR") && /izkljuceno dejanje/.test(A.log), "poskus izkljucenega dejanja: POZOR v dnevniku");
    } finally {
      await pool.query("DELETE FROM predlogi_dejanj WHERE razlog = 'simulacija'");
      await pool.query(`ALTER TABLE predlogi_dejanj ADD CONSTRAINT predlogi_dejanj_dejanje_check ${chk}`);
    }
    // #340 varovalke tudi ob nujni izvedbi: shranjene spremembe (vrstica mimo poti) z nevidnimi znaki ali tujim plakatom -> 400, nic se ne izvede
    for (const [spr, koda] of [[{ poster_url: "https://evil.example/p.jpg" }, "plakat_ni_dovoljen"], [{ title: "Dogodek \u202Eizkl" }, "nevidni_znaki"]]) {
      const id = (await pool.query("INSERT INTO predlogi_dejanj (agent_zeton_id, dejanje, cilj_tip, cilj_id, spremembe, razlog) VALUES ($1, 'event.uredi', 'event', $2, $3::jsonb, 'mimo poti') RETURNING id",
        [NUJNO_ID, E.izkl, JSON.stringify(spr)])).rows[0].id;
      const x = await izvedi(id, { potrditev: "potrjujem: uredi Dogodek izkl", seja: SEJA });
      assert(x.status === 400 && x.body.error === koda, `nujna izvedba znova preveri shranjene spremembe: ${koda}`, [x.status, x.body]);
      assert((await predlogVBazi(id)).stanje === "caka" && (await vrstica(E.izkl)).title === "Dogodek izkl" && (await vrstica(E.izkl)).poster_url === "https://x.test/p.jpg", `${koda}: nic se ne izvede`);
    }
    // enota: izkljucitev je neodvisna od belega seznama (tudi ce bi kdo dodal dejanje v DEJANJA)
    const ap = require(path.join(__dirname, "..", "agent_predlogi.js"));
    ap.DEJANJA.set("db.export", { cilj: "event", pot: "uredi", polja: [] });
    ap.DEJANJA.set("user.role", { cilj: "event", pot: "uredi", polja: ["role"] });
    assert(ap.nujnoIzkljuceno("db.export", {}) === "izvoz baze" && ap.nujnoIzkljuceno("user.role", { role: "admin" }) === "vloga admin/backup" && ap.nujnoIzkljuceno("user.role", { role: "backup" }),
      "nujnoIzkljuceno: izvoz in vloga admin/backup tudi, ce sta v DEJANJA");
    assert(ap.nujnoIzkljuceno("event.ustavi_prodajo", {}) === null && ap.nujnoIzkljuceno("event.uredi", { title: "Admin backup party" }) === null, "nujnoIzkljuceno: dovoljena dejanja (tudi naslov z besedo admin) niso izkljucena");
    ap.DEJANJA.delete("db.export"); ap.DEJANJA.delete("user.role");
    const kodaPredl = fs.readFileSync(path.join(__dirname, "..", "agent_predlogi.js"), "utf8");
    const iNujno = kodaPredl.indexOf('router.post("/predlogi/:id/izvedi-nujno"');
    assert(iNujno > 0 && kodaPredl.indexOf("nujnoIzkljuceno(p.dejanje", iNujno) > 0 && kodaPredl.indexOf("nujnoIzkljuceno(p.dejanje", iNujno) < kodaPredl.indexOf("DEJANJA.has(p.dejanje)", iNujno),
      "nujna pot preveri izkljucitve PRED belim seznamom");

    // ---------------- 7. mail: napaka po sprejemu, dokazana zavrnitev ----------------
    console.log("\n# 7. mail natanko enkrat ob napakah Resenda");
    const P_M1 = await nov(NASLOV(E.m1, "Dogodek m1 (agent)"));
    R.poslano.length = 0; R.rezim = ["reset"];
    r = await izvedi(P_M1, { potrditev: "potrjujem: preimenuj Dogodek m1", seja: SEJA });
    assert(r.status === 200 && (await vrstica(E.m1)).title === "Dogodek m1 (agent)", "izvedba uspe ne glede na mail", [r.status, r.body]);
    assert(await cakaj(async () => (await predlogVBazi(P_M1)).nujno_mail_poslano_at !== null, 8000), "napaka PO sprejemu (prekinjena povezava): pospravljalec mail ponovi (vsaj enkrat)");
    await pocakaj(800);
    const pM1 = await predlogVBazi(P_M1);
    assert(mailiZa(P_M1).length === 2 && pM1.nujno_mail_poskusi === 2 && pM1.nujno_mail_izid_neznan === false, "prekinjena povezava: 2 maila (dvojnik je dovoljen), nato nic vec", [mailiZa(P_M1).length, pM1.nujno_mail_poskusi]);

    const P_M2 = await nov(NASLOV(E.m2, "Dogodek m2 (agent)"));
    R.poslano.length = 0; R.napaka = 1;
    r = await izvedi(P_M2, { potrditev: "potrjujem: preimenuj Dogodek m2", seja: SEJA });
    assert(r.status === 200, "izvedba uspe", r.status);
    assert(await cakaj(async () => (await predlogVBazi(P_M2)).nujno_mail_poslano_at !== null, 6000), "dokazana zavrnitev (422) -> ponovitev, mail poslan");
    await pocakaj(800);
    const pM2 = await predlogVBazi(P_M2);
    assert(mailiMartinu().length === 1 && pM2.nujno_mail_poskusi === 2, "natanko en sprejet mail po zavrnitvi (2 poskusa)", [mailiMartinu().length, pM2.nujno_mail_poskusi]);

    // VSAJ ENKRAT (S2): izvedena nujna dejanja vstavljena v bazo (nujno_at pred 2 dnevoma: ne steje v mejo 24 h, pospravljalec jih vidi 7 dni)
    const izvedeno = async (polja = {}) => (await pool.query(
      `INSERT INTO predlogi_dejanj (agent_zeton_id, dejanje, cilj_tip, cilj_id, spremembe, prej, razlog, stanje, odloceno_at, nujno_potrditev, nujno_seja, nujno_at,
                                    nujno_mail_poskusi, nujno_mail_prevzeto_at, nujno_mail_izid_neznan)
       VALUES ($1, 'event.ustavi_prodajo', 'event', $2, '{"sales_paused": true}', '{"sales_paused": false}', 'mail', 'potrjen', NOW() - INTERVAL '2 days', 'potrjujem: mail', $3,
               NOW() - INTERVAL '2 days', $4, $5, $6) RETURNING id`,
      [NUJNO_ID, E.mail, SEJA, polja.poskusi || 0, polja.prevzeto || null, polja.neznan || false])).rows[0].id;
    R.rezim = ["zamik"];
    const P_ROK = await izvedeno();
    assert(await cakaj(async () => (await predlogVBazi(P_ROK)).nujno_mail_poslano_at !== null, 10000), "rok Resenda (izid neznan) -> pospravljalec ponovi, mail potrjen");
    assert(mailiZa(P_ROK).length === 2 && (await predlogVBazi(P_ROK)).nujno_mail_poskusi === 2, "rok: 2 maila (drugi poskus poslje)", [mailiZa(P_ROK).length]);
    R.rezim = ["json500"];
    const P_500 = await izvedeno();
    assert(await cakaj(async () => (await predlogVBazi(P_500)).nujno_mail_poslano_at !== null, 10000), "5xx Resenda -> ponovitev, mail potrjen");
    assert(mailiZa(P_500).length === 2, "5xx: 2 maila", mailiZa(P_500).length);
    // padec procesa med rezervacijo in klicem Resenda: rezervacija brez poslano_at (stara) se prevzame znova
    const P_PAD = await izvedeno({ poskusi: 1, prevzeto: new Date(Date.now() - 10 * 60000), neznan: true });
    assert(await cakaj(async () => (await predlogVBazi(P_PAD)).nujno_mail_poslano_at !== null, 6000), "padec med rezervacijo in klicem -> pospravljalec poslje");
    assert(mailiZa(P_PAD).length === 1 && (await predlogVBazi(P_PAD)).nujno_mail_poskusi === 2, "padec: en mail, drugi poskus", mailiZa(P_PAD).length);
    const sveza = await izvedeno({ poskusi: 1, prevzeto: new Date(), neznan: true });   // poskus v teku (sveza rezervacija) se ne podvoji takoj
    await pocakaj(700);
    assert(mailiZa(sveza).length === 0, "sveza rezervacija (poskus v teku) se ne prevzame pred premorom");
    await pool.query("UPDATE predlogi_dejanj SET nujno_pregledano_at = NOW() WHERE id = $1", [sveza]);
    // 5 neuspehov: POZOR + Sentry error, rdece opozorilo v /admin/api/opozorila in warnings_red
    R.napaka = 1000;
    const P_IZC = await izvedeno();
    assert(await cakaj(async () => (await predlogVBazi(P_IZC)).nujno_mail_poskusi === 5, 20000), "5 poskusov (narascajoc premor)");
    await pocakaj(700);
    const pIzc = await predlogVBazi(P_IZC);
    assert(pIzc.nujno_mail_poskusi === 5 && pIzc.nujno_mail_poslano_at === null, "po 5 poskusih ni vec poskusov", pIzc.nujno_mail_poskusi);
    assert(vsi().some((x) => /\[agent-nujno\] POZOR: \d+ nujnih dejanj agenta brez poslanega maila/.test(x.log)), "izcrpano: [agent-nujno] POZOR v dnevniku");
    R.napaka = 0;
    const op = await api(PORT, "GET", "/admin/api/opozorila", T.admin);
    const rdece = (op.body.items || []).filter((o) => o.vrsta === "nujno_mail_neposlan");
    assert(op.status === 200 && rdece.some((o) => o.cilj_id === P_IZC && o.resnost === "rdece") && !rdece.some((o) => o.cilj_id === P_OK || o.cilj_id === sveza),
      "rdece opozorilo za nepregledano nujno dejanje brez poslanega maila (ne za poslane in pregledane)", rdece);
    nicOsebnega("opozorilo nujno_mail_neposlan", JSON.stringify(rdece));
    const sm0 = await api(PORT, "GET", "/admin/api/summary", T.admin);
    assert(sm0.status === 200 && typeof sm0.body.warnings_red === "number" && sm0.body.warnings_red >= 1, "summary.warnings_red steje rdece opozorilo", sm0.body.warnings_red);
    const kodaSentry = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8");
    assert(/javiNapako: \(e\) => sentry\.porociNapako\(e, "agent-nujno"\)/.test(kodaSentry), "izcrpan mail gre v Sentry kot napaka (porociNapako), ne samo opozorilo");

    // ---------------- 8. meja 3 na 24 h ----------------
    console.log("\n# 8. meja 3 nujna dejanja na 24 h (globalno)");
    const P_4 = await nov(NASLOV(E.meja, "Dogodek meja (agent)"));
    r = await izvedi(P_4, { potrditev: "potrjujem: preimenuj Dogodek meja", seja: SEJA });
    assert(r.status === 429 && r.body.error === "nujno_meja", "4. nujno dejanje v 24 h -> 429 nujno_meja", [r.status, r.body]);
    assert((await vrstica(E.meja)).title === "Dogodek meja" && (await predlogVBazi(P_4)).stanje === "caka", "429: nic se ne izvede, predlog ostane caka");
    const P_4b = await nov(NASLOV(E.meja, "Dogodek meja (drug zeton)"), NUJNO2);
    r = await izvedi(P_4b, { potrditev: "potrjujem: preimenuj Dogodek meja", seja: SEJA }, NUJNO2);
    assert(r.status === 429 && r.body.error === "nujno_meja", "meja je globalna: drug zeton -> 429", [r.status, r.body]);
    r = await api(PORT, "POST", `/admin/api/predlogi/${P_4}/potrdi`, T.admin, {});
    assert(r.status === 200 && (await vrstica(E.meja)).title === "Dogodek meja (agent)", "admin v panelu predlog se vedno potrdi (meja velja samo za nujni nacin)", [r.status, r.body]);

    // 4 hkratni klici iz 4 procesov (semafor agenta je na proces) -> natanko 3
    await pool.query("UPDATE predlogi_dejanj SET nujno_at = nujno_at - INTERVAL '25 hours' WHERE nujno_at IS NOT NULL");
    const hk = [];
    for (const k of ["h1", "h2", "h3", "h4"]) hk.push(await nov(NASLOV(E[k], `Dogodek ${k} (agent)`)));
    R.poslano.length = 0;
    const porti = [PORT, ...PORTI_H];
    const izidi = await Promise.all(hk.map((id, i) => izvedi(id, { potrditev: "potrjujem: preimenuj vse stiri", seja: SEJA }, NUJNO, porti[i])));
    const s200 = izidi.filter((x) => x.status === 200).length, s429 = izidi.filter((x) => x.status === 429 && x.body.error === "nujno_meja").length;
    assert(s200 === 3 && s429 === 1, "4 hkratni klici (4 procesi) -> natanko 3 izvedbe in en 429", izidi.map((x) => [x.status, x.body && x.body.error]));
    const spremenjeni = (await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE id = ANY($1::int[]) AND title LIKE '%(agent)'", [[E.h1, E.h2, E.h3, E.h4]])).rows[0].n;
    assert(spremenjeni === 3, "spremenjeni so natanko 3 dogodki", spremenjeni);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM predlogi_dejanj WHERE nujno_at > NOW() - INTERVAL '24 hours'")).rows[0].n === 3, "v bazi natanko 3 nujne izvedbe v 24 h");
    await cakaj(() => mailiMartinu().length >= 3, 6000);
    await pocakaj(1500);
    assert(mailiMartinu().length === 3, "natanko 3 maili (4 procesi, vsak s svojim pospravljalcem)", mailiMartinu().length);
    // drsno okno: najstarejsa izvedba gre cez 24 h -> spet ena prosta
    const najst = (await pool.query("SELECT id FROM predlogi_dejanj WHERE nujno_at > NOW() - INTERVAL '24 hours' ORDER BY nujno_at, id LIMIT 1")).rows[0].id;
    await pool.query("UPDATE predlogi_dejanj SET nujno_at = NOW() - INTERVAL '24 hours 1 minute' WHERE id = $1", [najst]);
    const P_D = await nov(NASLOV(E.drsno, "Dogodek drsno (agent)"));
    r = await izvedi(P_D, { potrditev: "potrjujem: preimenuj Dogodek drsno", seja: SEJA });
    assert(r.status === 200, "drsno okno 24 h: ko gre najstarejsa cez 24 h, je ena izvedba spet mogoca", [r.status, r.body]);
    const zadnji = izidi.find((x) => x.status === 429);
    r = await izvedi(hk[izidi.indexOf(zadnji)], { potrditev: "potrjujem: preimenuj vse stiri", seja: SEJA });
    assert(r.status === 429, "takoj nato spet 429", r.status);
    r = await api(PORTI_H[0], "GET", "/admin/api/predlogi/nujno", T.admin);
    assert(r.status === 200 && r.body.meja_24h === 3, "AGENT_NUJNO_NA_24H=5 ne dvigne meje (ostane 3)", r.body.meja_24h);

    // N3: tekme z adminom in zaklepi
    await pool.query("UPDATE predlogi_dejanj SET nujno_at = nujno_at - INTERVAL '25 hours' WHERE nujno_at > NOW() - INTERVAL '24 hours'");
    const P_SK = await nov(NASLOV(E.sk, "Dogodek sk (agent)"));
    const [xn, xa] = await Promise.all([izvedi(P_SK, { potrditev: "potrjujem: preimenuj Dogodek sk", seja: SEJA }), api(PORT_OFF, "POST", `/admin/api/predlogi/${P_SK}/potrdi`, T.admin, {})]);
    const dejSk = (await pool.query("SELECT COUNT(*)::int AS n FROM admin_dejanja WHERE predlog_id = $1 AND dejanje = 'event.update'", [P_SK])).rows[0].n;
    assert([xn.status, xa.status].filter((x) => x === 200).length === 1 && [xn.status, xa.status].includes(409) && dejSk === 1 && (await vrstica(E.sk)).title === "Dogodek sk (agent)",
      "hkratna nujna izvedba in admin Potrdi -> natanko ena sprememba", [xn.status, xa.status, dejSk]);
    const P_ZV = await nov(NASLOV(E.zv, "Dogodek zv (agent)"));
    {
      const k = new pg.Client({ connectionString: DB }); await k.connect();
      await k.query("BEGIN"); await k.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [E.zv]);
      const obljuba = izvedi(P_ZV, { potrditev: "potrjujem: preimenuj Dogodek zv", seja: SEJA });
      assert(await nekdoCakaZaklep(), "nujni klic caka na vrstico dogodka");
      const zv = await api(PORT, "POST", `/admin/api/predlogi/${P_ZV}/zavrni`, T.admin, {}, 5000).catch((e) => ({ status: 0, body: String(e) }));
      await k.query("ROLLBACK"); await k.end();
      const x = await obljuba;
      assert(zv.status === 200 && x.status === 409 && x.body.error === "predlog_ne_caka" && (await vrstica(E.zv)).title === "Dogodek zv" && (await predlogVBazi(P_ZV)).stanje === "zavrnjen",
        "admin Zavrni med cakanjem nujnega klica -> nujni klic 409, nic se ne spremeni", [zv.status, x.status, x.body]);
    }
    // N2: nujni klic, ki caka na drugo nujno izvedbo (advisory 73121), NE drzi vrstice svojega dogodka
    const P_N2A = await nov(NASLOV(E.n2a, "Dogodek n2a (agent)"));
    const P_N2B = await nov(NASLOV(E.n2b, "Dogodek n2b (agent)"));
    {
      const k = new pg.Client({ connectionString: DB }); await k.connect();
      await k.query("BEGIN"); await k.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [E.n2a]);
      const oa = izvedi(P_N2A, { potrditev: "potrjujem: preimenuj Dogodek n2a", seja: SEJA });                 // drzi 73121, caka na vrstico n2a
      assert(await nekdoCakaZaklep(1), "prvi nujni klic caka na vrstico dogodka");
      const ob = izvedi(P_N2B, { potrditev: "potrjujem: preimenuj Dogodek n2b", seja: SEJA }, NUJNO, PORTI_H[1]);   // caka na 73121
      assert(await nekdoCakaZaklep(2), "drugi nujni klic caka na globalni zaklep nujnih izvedb");
      const k2 = new pg.Client({ connectionString: DB }); await k2.connect();
      let prosta = false;
      try { await k2.query("BEGIN"); await k2.query("SET LOCAL lock_timeout = 300"); await k2.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [E.n2b]); prosta = true; } catch (_) { prosta = false; }
      await k2.query("ROLLBACK").catch(() => {}); await k2.end();
      assert(prosta, "N2: med cakanjem na drugo nujno izvedbo vrstica dogodka n2b NI zaklenjena (nakup in admin nista blokirana)");
      await k.query("ROLLBACK"); await k.end();
      const [ra, rb] = await Promise.all([oa, ob]);
      assert(ra.status === 200 && rb.status === 200, "po sprostitvi obe nujni izvedbi uspeta (brez mrtve zanke)", [ra.status, rb.status, ra.body, rb.body]);
    }
    for (const port of [PORT, PORT_OFF]) {
      const x = await api(port, "POST", `/agent/api/predlogi/${P_N2A}/IZVEDI-NUJNO`, NUJNO, { potrditev: "potrjujem: x x", seja: SEJA });
      assert(x.status === 405, `/IZVEDI-NUJNO (velike crke) -> 405 ${port === PORT_OFF ? "(tudi ob AGENT_NUJNO=0)" : ""}`, [x.status, x.body]);
    }

    // ---------------- 9. panel ----------------
    console.log("\n# 9. panel: rdec pas in »Pregledal sem«");
    r = await api(PORT, "GET", "/admin/api/predlogi/nujno", T.admin);
    const nepregl = (await pool.query("SELECT COUNT(*)::int AS n FROM predlogi_dejanj WHERE nujno_at IS NOT NULL AND nujno_pregledano_at IS NULL")).rows[0].n;
    assert(r.status === 200 && r.body.nepregledanih === nepregl && r.body.items.length === nepregl && r.body.meja_24h === 3, "GET /admin/api/predlogi/nujno: vsa nepregledana", [r.status, r.body.nepregledanih, nepregl]);
    const it = r.body.items.find((x) => x.id === P_OK);
    assert(it && it.nujno_potrditev === POTRDI + "\n(Martin)" && it.nujno_seja === SEJA && it.mail === "poslan" && it.cilj_naslov === "Dogodek pavza", "postavka: citat, seja, stanje maila, cilj", it);
    assert(r.body.items.find((x) => x.id === P_IZC).mail === "ni_poslan" && r.body.items.find((x) => x.id === P_M1).mail === "poslan", "postavka: stanje maila (ni_poslan po izcrpanju, poslan po ponovitvi)");
    const sm = await api(PORT, "GET", "/admin/api/summary", T.admin);
    assert(sm.status === 200 && sm.body.nujno_nepregledanih === nepregl, "summary.nujno_nepregledanih", sm.body.nujno_nepregledanih);
    r = await api(PORT, "GET", "/admin/api/predlogi/nujno", T.poslovni);
    assert(r.status === 403, "ne-admin -> 403", r.status);
    r = await api(PORT, "GET", "/admin/api/predlogi/nujno", NUJNO);
    assert(r.status === 403, "zeton agenta na /admin/api/predlogi/nujno -> 403", r.status);
    r = await api(PORT, "POST", `/admin/api/predlogi/${P_OK}/nujno-pregledano`, NUJNO, {});
    assert(r.status === 403, "agent si nujnega dejanja ne more oznaciti kot pregledanega -> 403", r.status);
    r = await api(PORT, "POST", `/admin/api/predlogi/${P_OK}/nujno-pregledano`, T.admin, { reason: "ok, res sem potrdil" });
    assert(r.status === 200 && r.body.predlog.nujno_pregledal_admin_id === adminId, "Pregledal sem -> 200", [r.status, r.body]);
    const zp = (await pool.query("SELECT * FROM admin_dejanja WHERE dejanje = 'agent.nujno_pregledano' AND predlog_id = $1", [P_OK])).rows;
    assert(zp.length === 1 && zp[0].admin_user_id === adminId && zp[0].nujno === false, "admin_dejanja agent.nujno_pregledano pod adminom", zp);
    r = await api(PORT, "POST", `/admin/api/predlogi/${P_OK}/nujno-pregledano`, T.admin, {});
    assert(r.status === 409 && r.body.error === "ze_pregledano", "drugic -> 409 ze_pregledano", [r.status, r.body]);
    r = await api(PORT, "POST", `/admin/api/predlogi/${P_4}/nujno-pregledano`, T.admin, {});
    assert(r.status === 409 && r.body.error === "ni_nujno", "predlog brez nujne izvedbe -> 409 ni_nujno", [r.status, r.body]);
    r = await api(PORT, "GET", "/admin/api/predlogi/nujno", T.admin);
    assert(r.body.nepregledanih === nepregl - 1 && !r.body.items.some((x) => x.id === P_OK), "po pregledu izgine iz rdecega pasu", r.body.nepregledanih);
    r = await api(PORT, "GET", "/admin/api/predlogi/nujno?vse=1", T.admin);
    assert(r.body.items.some((x) => x.id === P_OK && x.nujno_pregledano_at), "?vse=1 vrne tudi pregledana");
    r = await api(PORT, "GET", `/admin/api/audit?target_type=event&target_id=${E.pavza}`, T.admin);
    assert(r.status === 200 && r.body.some((x) => x.dejanje === "event.sales_pause" && x.nujno === true && x.agent_zeton_id === NUJNO_ID), "N5: /admin/api/audit ima polje nujno", r.body);
    r = await api(PORT, "GET", `/admin/api/events/${E.pavza}`, T.admin);
    assert(r.status === 200 && (r.body.audit || []).some((x) => x.nujno === true), "N5: zgodovina dogodka (GET /admin/api/events/:id) ima polje nujno", r.body.audit);
    const kodaDog = fs.readFileSync(path.join(__dirname, "..", "admin", "dogodki.js"), "utf8");
    assert(/a\.nujno === true \? h\("span", \{ class: "znacka slabo" \}, "NUJNO \(agent\)"\)/.test(kodaDog), "N5: panel (zgodovina dogodka) pokaze oznako »NUJNO (agent)«");
    r = await api(PORT, "GET", "/agent/api/audit?target_type=predlog", NUJNO);
    nicOsebnega("agent /audit po nujnih izvedbah", r.text);
    assert(!r.text.includes(POTRDI), "agent /audit ne vrne citata (razlog ne gre ven)");

    // ---------------- 10. sken in nakup ----------------
    console.log("\n# 10. sken nedotaknjen");
    assert(!/skenPool/.test(kodaPredl.replace(/\/\/.*$/gm, "")), "agent_predlogi.js ne uporablja skenPool (koda brez komentarjev)");
    const vsaKoda = fs.readdirSync(path.join(__dirname, "..")).filter((f) => f.endsWith(".js")).map((f) => [f, fs.readFileSync(path.join(__dirname, "..", f), "utf8")]);
    const klici = vsaKoda.flatMap(([f, k]) => (k.match(/nujnoMailPoslji\(/g) || []).map(() => f));
    assert(klici.every((f) => f === "agent_predlogi.js") && klici.length === 3, "mail o nujnem dejanju se poslje samo iz agent_predlogi.js (definicija, izvedba, pospravljalec)", klici);
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack);
  } finally {
    for (const s of vsi()) s.proc.kill("SIGTERM");
    jwksServer.close(); resendServer.close();
    await pool.end();
  }
  const dnevnik = vsi().map((s) => s.log).join("\n");
  if (/outly_agent_[A-Za-z0-9_-]{43}/.test(dnevnik)) { fail++; console.log("  ✗ zeton agenta v dnevniku streznika"); }
  if (dnevnik.includes("kupec-nujno@")) { fail++; console.log("  ✗ e-naslov kupca v dnevniku streznika"); }
  if (fail && process.env.IZPIS_DNEVNIKA) console.log(dnevnik.slice(-6000));
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
