#!/usr/bin/env node
/**
 * Test: VRATAR NA SKENERJU NE VIDI E-NASLOVOV (I21, 8. 10. 2026). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_vratar_sken_email.js
 * Vzorec kot test_guest_lista_obvestilo.js: lokalni JWKS (3976), backend na svojem portu (3176), TRUNCATE na zacetku.
 *
 * Pred popravkom je POST /business/tickets/scan vratarju vrnil ticket.buyer_email in ticket.holder_email NAVADNIH kupcev
 * (I21 je pokrival samo seznam GET /business/events/:id/tickets). Preverjeno v VSEH vejah odgovora:
 *  1  ok, already_used, status != valid (refunded), event_cancelled: vratar brez buyer_email/holder_email (in brez znaka @ v odgovoru)
 *  2  vratar: uporabnisko ime imetnika, QR-neodvisna polja (public_ref, holder_username) ostanejo
 *  3  lastnik in manager: e-naslova viden kot doslej (ok in event_cancelled), imetnik po prenosu = e-naslov prejemnika
 *  4  scan-batch in scan-list: v odgovoru ni e-naslovov (nobena vloga)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3176, JWKS_PORT = 3976;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-vratar-sken-email";
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
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}

let srv = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), vratar: zeton("vratar@outly.si", uuid(2)), manager: zeton("manager@outly.si", uuid(3)),
      ana: zeton("ana@outly.si", uuid(4)), bor: zeton("bor@outly.si", uuid(5)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");

    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (title) => {
      const x = await api("POST", "/events", T.lastnik, { clubId: 1, title, startAt: cezDan, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
      assert(x.status === 201, `dogodek ${title}`, x.body); return x.body.id;
    };
    const evA = await dogodek("Sken A");
    const evB = await dogodek("Sken B (odpovedan)");
    let r = await api("POST", `/events/${evA}/orders`, T.ana, { quantity: 6 });
    assert(r.status === 201 && r.body.tickets.length === 6, "ana kupi 6 vstopnic na A", r.body);
    const a = r.body.tickets.map(t => t.serial);
    r = await api("POST", `/events/${evB}/orders`, T.ana, { quantity: 2 });
    assert(r.status === 201 && r.body.tickets.length === 2, "ana kupi 2 vstopnici na B", r.body);
    const b = r.body.tickets.map(t => t.serial);
    // vrata odprta, dogodek B odpovedan (naročilo ostane placano), a[1] vrnjena, a[2] in a[4] preneseni na bora
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '1 hour' WHERE id = ANY($1::int[])", [[evA, evB]]);
    await pool.query("UPDATE events SET status='cancelled' WHERE id=$1", [evB]);
    await pool.query("UPDATE tickets SET status='refunded' WHERE serial=$1", [a[1]]);
    await pool.query("UPDATE tickets SET holder_user_id=(SELECT id FROM users WHERE email='bor@outly.si') WHERE serial = ANY($1::uuid[])", [[a[2], a[4]]]);

    const brezEposte = (x) => x.body && x.body.ticket && !("buyer_email" in x.body.ticket) && !("holder_email" in x.body.ticket) && !/@/.test(x.text);
    const sken = (zt, serial) => api("POST", "/business/tickets/scan", zt, { serial });

    console.log("\n# 1. Vratar: nobena veja odgovora ne vsebuje e-naslova");
    r = await sken(T.vratar, a[0]);
    assert(r.status === 200 && r.body.result === "ok" && brezEposte(r), "ok: brez buyer_email in holder_email", r.body);
    r = await sken(T.vratar, a[0]);
    assert(r.status === 409 && r.body.result === "already_used" && brezEposte(r), "already_used: brez e-naslovov", r.body);
    r = await sken(T.vratar, a[1]);
    assert(r.status === 409 && r.body.result === "refunded" && brezEposte(r), "status != valid (refunded): brez e-naslovov", r.body);
    r = await sken(T.vratar, b[0]);
    assert(r.status === 409 && r.body.result === "event_cancelled" && brezEposte(r), "event_cancelled: brez e-naslovov", r.body);
    r = await sken(T.vratar, a[2]);
    assert(r.status === 200 && r.body.result === "ok" && brezEposte(r), "preneseno na bora (ok): brez e-naslova kupca ANI imetnika", r.body);

    console.log("\n# 2. Vratar: ostalo ostane");
    assert(r.body.ticket.holder_username === "bor" && r.body.ticket.public_ref && r.body.ticket.serial === a[2] && r.body.ticket.transferred === true, "uporabnisko ime imetnika, public_ref, serial, transferred", r.body.ticket);
    // QR (kot v aplikaciji): isto
    const qr = (await api("GET", `/business/events/${evA}/tickets`, T.lastnik)).body.find(t => t.serial === a[3]).qr;
    r = await api("POST", "/business/tickets/scan", T.vratar, { qr });
    assert(r.status === 200 && r.body.result === "ok" && brezEposte(r), "sken s QR: ok, brez e-naslovov", r.body);

    console.log("\n# 3. Manager in lastnik: e-naslova kot doslej");
    r = await sken(T.manager, a[4]);
    assert(r.status === 200 && r.body.ticket.buyer_email === "ana@outly.si" && r.body.ticket.holder_email === "bor@outly.si", "manager (ok, preneseno): buyer_email ana, holder_email bor", r.body.ticket);
    r = await sken(T.lastnik, a[5]);
    assert(r.status === 200 && r.body.ticket.buyer_email === "ana@outly.si" && r.body.ticket.holder_email === "ana@outly.si", "lastnik (ok): buyer_email in holder_email ana", r.body.ticket);
    r = await sken(T.lastnik, a[5]);
    assert(r.status === 409 && r.body.result === "already_used" && r.body.ticket.buyer_email === "ana@outly.si", "lastnik (already_used): e-naslov viden", r.body);
    r = await sken(T.manager, b[1]);
    assert(r.status === 409 && r.body.result === "event_cancelled" && r.body.ticket.buyer_email === "ana@outly.si" && r.body.ticket.holder_email === "ana@outly.si", "manager (event_cancelled): e-naslova vidna", r.body);

    console.log("\n# 4. scan-batch in scan-list: brez e-naslovov");
    r = await api("POST", "/business/tickets/scan-batch", T.vratar, { device_id: crypto.randomUUID(),
      scans: [{ client_scan_id: crypto.randomUUID(), serial: b[0] }, { client_scan_id: crypto.randomUUID(), serial: a[3] }] });
    assert(r.status === 200 && r.body.results.length === 2 && !/@/.test(r.text) && r.body.results.every(x => !("ticket" in x)), "scan-batch (vratar): rezultati brez ticket in brez @", r.text);
    for (const k of ["vratar", "manager", "lastnik"]) {
      r = await api("GET", `/business/events/${evA}/scan-list`, T[k]);
      assert(r.status === 200 && r.body.tickets.length === 6 && !/@/.test(r.text) && r.body.tickets.every(x => !("buyer_email" in x) && !("holder_email" in x)), `scan-list (${k}): brez e-naslovov`, r.status);
    }
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    srv.kill(); jwksServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + log.split("\n").slice(-40).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
