#!/usr/bin/env node
/**
 * Idempotenten rocni »Check in« (issue #308): POST /business/tickets/scan z neobveznim client_scan_id.
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_sken_idempotenca.js
 *
 * Skripta sama dvigne lokalni JWKS streznik (port 3312), podpise ES256 zetone in zazene backend na portu 3311.
 * Preveri: ponovitev istega client_scan_id = 200 ok z izvirnim used_at (brez novega zapisa); drug id / brez id / drug clan
 * ekipe = 409 already_used; socasno N zahtevkov z istim id = vsi ok, en zapis; socasno z razlicnimi id = natanko en ok (I1/I14);
 * stari odjemalci brez polja: vedenje kot prej; neveljaven id se PREZRE (sken kot brez polja, client_scan_id_ignored: true) — vrata
 * ne smejo zavrniti gosta zaradi napake odjemalca; ponovitev starejsa od 10 min (SKEN_PONOVITEV_MS) -> already_used.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3311, JWKS_PORT = 3312;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-sken-idem";
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
function uuid(n) { return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`; }
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path, token, body, headers) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...(headers || {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
const sken = (token, body, ua) => api("POST", "/business/tickets/scan", token, body, ua ? { "user-agent": ua } : undefined);

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), vratar: zeton("vratar@outly.si", uuid(2)), ana: zeton("ana@outly.si", uuid(3)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman')");
    const vratarId = (await pool.query("SELECT id FROM users WHERE email='vratar@outly.si'")).rows[0].id;

    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Sken idem", startAt: cezDan, ticketPriceCents: 1500, capacity: 200, minAge: 0 });
    assert(r.status === 201, "dogodek ustvarjen", r.body);
    const dog = r.body.id;
    r = await api("POST", `/events/${dog}/orders`, T.ana, { quantity: 10 });
    assert(r.status === 201 && r.body.tickets.length === 10, "ana kupi 10 vstopnic", r.body);
    const v = r.body.tickets;
    await pool.query("UPDATE tickets SET created_at = NOW() - INTERVAL '2 days'");
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '1 hour' WHERE id=$1", [dog]);   // vrata odprta
    const stanje = async (serial) => (await pool.query("SELECT status, used_at, used_by_user_id, scan_device FROM tickets WHERE serial=$1", [serial])).rows[0];

    console.log("\n# Stari odjemalec brez client_scan_id: vedenje kot prej");
    r = await sken(T.vratar, { qr: v[0].qr }, "OutlyStari/1.0");
    assert(r.status === 200 && r.body.result === "ok", "prvi sken brez id -> 200 ok", r.body);
    assert(r.body.replayed === undefined, "brez id: polja replayed ni (odgovor kot prej)", r.body);
    let s = await stanje(v[0].serial);
    assert(s.scan_device === "OutlyStari/1.0", "brez id: scan_device = user-agent (kot prej)", s);
    r = await sken(T.vratar, { qr: v[0].qr }, "OutlyStari/1.0");
    assert(r.status === 409 && r.body.result === "already_used" && r.body.used_at, "drugi sken brez id -> 409 already_used z used_at", r.body);
    r = await sken(T.vratar, { qr: v[0].qr, client_scan_id: "OutlyStari/1.0" }, "OutlyStari/1.0");
    assert(r.status === 409 && r.body.result === "already_used" && r.body.replayed === undefined && r.body.client_scan_id_ignored === true,
      "id z znakom '/' (= user-agent) se prezre -> already_used, ne zadene user-agenta", r.body);

    console.log("\n# Ponovitev z istim client_scan_id");
    const A = crypto.randomUUID(), B = crypto.randomUUID();
    r = await sken(T.vratar, { serial: v[1].serial, client_scan_id: A });
    assert(r.status === 200 && r.body.result === "ok" && r.body.ticket && r.body.ticket.used_at, "rocni Check in (serial) z id A -> 200 ok", r.body);
    const usedPrvi = r.body.ticket.used_at;
    assert(r.body.used_at === usedPrvi, "ok odgovor ima tudi used_at na vrhu (= ticket.used_at)", r.body.used_at);
    s = await stanje(v[1].serial);
    assert(s.status === "used" && s.scan_device === `scan|${A}` && Number(s.used_by_user_id) === Number(vratarId), "baza: used, scan_device = scan|A, used_by = vratar", s);
    const usedBaza = s.used_at.toISOString();
    await new Promise(x => setTimeout(x, 30));
    r = await sken(T.vratar, { serial: v[1].serial, client_scan_id: A });
    assert(r.status === 200 && r.body.result === "ok" && r.body.replayed === true, "ponovitev z id A -> 200 ok, replayed: true", r.body);
    assert(r.body.ticket && r.body.ticket.used_at === usedPrvi && r.body.used_at === usedPrvi, "ponovitev: izvirni used_at (ticket.used_at in used_at)", [r.body.ticket && r.body.ticket.used_at, r.body.used_at, usedPrvi]);
    assert(r.body.ticket && r.body.ticket.status === "used" && r.body.table_service_created === false, "ponovitev: status used, table_service_created false", r.body);
    assert(r.body.ticket && !("scan_device" in r.body.ticket) && !("zaznamek_skena" in r.body.ticket) && !("skeniral_id" in r.body.ticket) && !("used_by_user_id" in r.body.ticket), "odgovor ne razkrije scan_device / used_by", r.body.ticket);
    assert(r.body.ticket && !("buyer_email" in r.body.ticket) && !("holder_email" in r.body.ticket), "vratar ob ponovitvi ne vidi e-naslovov (I21)", r.body.ticket);
    r = await sken(T.vratar, { qr: v[1].qr, client_scan_id: A });
    assert(r.status === 200 && r.body.result === "ok" && r.body.ticket.used_at === usedPrvi, "ponovitev z id A prek qr (namesto serial) -> ok, isti used_at", r.body);
    s = await stanje(v[1].serial);
    assert(s.used_at.toISOString() === usedBaza && s.scan_device === `scan|${A}`, "baza ob ponovitvah nespremenjena", s);

    console.log("\n# Drug id, brez id, drug clan ekipe -> already_used");
    r = await sken(T.vratar, { serial: v[1].serial, client_scan_id: B });
    assert(r.status === 409 && r.body.result === "already_used" && r.body.used_at === usedPrvi, "drug id B -> 409 already_used z used_at prvega", r.body);
    r = await sken(T.vratar, { serial: v[1].serial });
    assert(r.status === 409 && r.body.result === "already_used", "brez id na ze vpisani -> 409 already_used", r.body);
    r = await sken(T.lastnik, { serial: v[1].serial, client_scan_id: A });
    assert(r.status === 409 && r.body.result === "already_used", "drug clan ekipe (lastnik) z istim id A -> 409 already_used", r.body);
    r = await sken(T.vratar, { serial: v[0].serial, client_scan_id: A });
    assert(r.status === 409 && r.body.result === "already_used", "id A na DRUGI vstopnici (vpisani brez id) -> already_used", r.body);

    console.log("\n# Neveljaven client_scan_id: sken NE pade (prezre se, vedenje kot brez polja)");
    r = await sken(T.vratar, { serial: v[2].serial, client_scan_id: "a".repeat(65) }, "OutlyHrosc/1.0");
    assert(r.status === 200 && r.body.result === "ok" && r.body.client_scan_id_ignored === true && r.body.replayed === undefined,
      "predolg id na veljavni vstopnici -> 200 ok (gost spuscen), client_scan_id_ignored", r.body);
    s = await stanje(v[2].serial);
    assert(s.status === "used" && s.scan_device === "OutlyHrosc/1.0", "prezrt id: scan_device = user-agent (kot brez polja)", s);
    for (const [opis, cid] of [["predolg (65 znakov)", "a".repeat(65)], ["prazen niz", ""], ["stevilo", 12345], ["presledek", "a b"], ["objekt", { x: 1 }], ["pipe", "a|b"], ["seznam", ["x"]], ["true", true]]) {
      r = await sken(T.vratar, { serial: v[2].serial, client_scan_id: cid }, "OutlyHrosc/1.0");
      assert(r.status === 409 && r.body.result === "already_used" && r.body.client_scan_id_ignored === true, `id ${opis} -> prezrt, ponovitev = already_used (ne 400/500)`, r.body);
    }
    r = await sken(T.vratar, { serial: v[8].serial, client_scan_id: null });
    assert(r.status === 200 && r.body.result === "ok" && r.body.client_scan_id_ignored === undefined, "client_scan_id: null = kot brez polja -> ok, brez client_scan_id_ignored", r.body);

    console.log("\n# Ponovitev po izteku okna (10 min) -> already_used");
    const F = crypto.randomUUID();
    r = await sken(T.vratar, { serial: v[9].serial, client_scan_id: F });
    assert(r.status === 200 && r.body.result === "ok", "sken z id F -> ok", r.body);
    await pool.query("UPDATE tickets SET used_at = used_at - INTERVAL '9 minutes' WHERE serial=$1", [v[9].serial]);
    r = await sken(T.vratar, { serial: v[9].serial, client_scan_id: F });
    assert(r.status === 200 && r.body.result === "ok" && r.body.replayed === true, "ponovitev 9 min po vpisu -> se vedno ok, replayed", r.body);
    await pool.query("UPDATE tickets SET used_at = used_at - INTERVAL '2 minutes' WHERE serial=$1", [v[9].serial]);
    r = await sken(T.vratar, { serial: v[9].serial, client_scan_id: F });
    assert(r.status === 409 && r.body.result === "already_used" && r.body.used_at, "ponovitev 11 min po vpisu -> 409 already_used z used_at", r.body);

    console.log("\n# Socasno N zahtevkov z istim client_scan_id");
    const N = 20, C = crypto.randomUUID();
    const vsi = await Promise.all(Array.from({ length: N }, () => sken(T.vratar, { serial: v[3].serial, client_scan_id: C })));
    const st = vsi.map(x => `${x.status}:${x.body && x.body.result}`);
    assert(vsi.every(x => x.status === 200 && x.body.result === "ok"), `${N} hkrati z istim id: vsi 200 ok`, st);
    const casi = new Set(vsi.map(x => x.body && x.body.ticket && x.body.ticket.used_at));
    assert(vsi.every(x => x.body.used_at === x.body.ticket.used_at), "vsak odgovor: used_at = ticket.used_at");
    assert(casi.size === 1 && !casi.has(undefined) && !casi.has(null), "vsi z istim used_at", [...casi]);
    assert(vsi.filter(x => x.body.replayed !== true).length === 1, "natanko en odgovor je prvi zapis (ostali replayed)", vsi.map(x => x.body.replayed));
    s = await stanje(v[3].serial);
    assert(s.status === "used" && s.scan_device === `scan|${C}` && new Date(s.used_at).toISOString() === new Date([...casi][0]).toISOString(), "baza: en zapis, used_at = vrnjen", s);

    console.log("\n# Socasno N zahtevkov z razlicnimi id (pravi dvojni sken, I1)");
    const raz = await Promise.all(Array.from({ length: N }, () => sken(T.vratar, { serial: v[4].serial, client_scan_id: crypto.randomUUID() })));
    assert(raz.filter(x => x.status === 200 && x.body.result === "ok").length === 1, `${N} razlicnih id hkrati: natanko 1 ok`, raz.map(x => `${x.status}:${x.body && x.body.result}`));
    assert(raz.filter(x => x.status === 409 && x.body.result === "already_used").length === N - 1, `ostalih ${N - 1}: already_used`);

    console.log("\n# Mesano socasno: isti id x10 + brez id x10");
    const D = crypto.randomUUID();
    const mes = await Promise.all(Array.from({ length: 20 }, (_, i) => sken(T.vratar, i % 2 ? { serial: v[5].serial } : { serial: v[5].serial, client_scan_id: D })));
    const okMes = mes.filter(x => x.status === 200 && x.body.result === "ok");
    s = await stanje(v[5].serial);
    const zmagalId = s.scan_device === `scan|${D}`;
    assert(okMes.length === (zmagalId ? 10 : 1), zmagalId ? "zmagal id D: 10 ok (vsi z D), 10 already_used" : "zmagal zahtevek brez id: 1 ok, ostali already_used", { ok: okMes.length, scan_device: s.scan_device });
    assert(mes.filter(x => x.status === 409 && x.body.result === "already_used").length === 20 - okMes.length, "ostali already_used, nobene napake 5xx", mes.map(x => x.status));

    console.log("\n# scan-batch zaznamek ne zadene /scan (razlicna predpona)");
    const E = crypto.randomUUID();
    r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [{ client_scan_id: E, device_id: "dev-1", serial: v[6].serial }] });
    assert(r.status === 200 && r.body.results[0].result === "ok", "scan-batch z id E -> ok", r.body);
    r = await sken(T.vratar, { serial: v[6].serial, client_scan_id: E });
    assert(r.status === 409 && r.body.result === "already_used", "/scan z istim id E po scan-batch -> already_used (zaznamka se ne mesata)", r.body);
    r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [{ client_scan_id: E, device_id: "dev-1", serial: v[6].serial }] });
    assert(r.status === 200 && r.body.results[0].result === "ok", "ponovitev scan-batch ostane ok (/scan ni pokvaril zaznamka)", r.body);

    console.log("\n# Druga pravila veljajo enako z id (neveljavna koda, neznana vstopnica)");
    r = await sken(T.vratar, { qr: "o2.x.y", client_scan_id: crypto.randomUUID() });
    assert(r.status === 400 && r.body.result === "invalid", "slaba koda z veljavnim id -> 400 invalid", r.body);
    r = await sken(T.vratar, { serial: uuid(999), client_scan_id: crypto.randomUUID() });
    assert(r.status === 404 && r.body.result === "unknown", "neznana vstopnica z id -> 404 unknown", r.body);
    r = await sken(T.ana, { serial: v[7].serial, client_scan_id: crypto.randomUUID() });
    assert(r.status === 403, "navaden uporabnik z id -> 403", r.status);
    r = await api("POST", "/business/tickets/scan", null, { serial: v[7].serial, client_scan_id: crypto.randomUUID() });
    assert(r.status === 401, "brez zetona z id -> 401", r.status);
    const used = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE status='used'")).rows[0].n;
    assert(used === 9, "v bazi je unovcenih natanko 9 vstopnic (v0..v6, v8, v9; v7 ne)", used);
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack);
  } finally {
    srv.kill(); jwksServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik backenda ---\n" + log.slice(-4000));
    console.log(`\n${ok} ok, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
