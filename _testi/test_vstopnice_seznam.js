#!/usr/bin/env node
/**
 * Test: SEZNAM VSTOPNIC DOGODKA PRI VEC KOT 1000 VSTOPNICAH (#277 N1, I45). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_vstopnice_seznam.js
 * Vzorec kot test_vratar_sken_email.js: lokalni JWKS (5782), backend na svojem portu (5781), TRUNCATE na zacetku.
 *
 * Pred popravkom je GET /business/events/:id/tickets imel LIMIT 1000 brez znaka, da je seznam odrezan: rocni »Check in«, iskanje in stevec
 * »sold« v odjemalcih pri > 1000 vstopnicah niso videli ostalih. Zdaj:
 *  1  brez parametrov: golo polje, najvec 1000 (oblika kot doslej, star odjemalec nespremenjen)
 *  2  limit/offset: ovojnica { tickets, counts, total, limit, offset, has_more, next_offset }; strani se ne prekrivajo in skupaj dajo vse vstopnice
 *  3  counts so neodvisni od reza (limit 0 = samo stevci), sold = valid + used, vrnjena/neveljavna ne stejejo kot prodana
 *  4  q: iskanje po public_ref, serialu, uporabniskem imenu; lastnik in manager tudi po e-naslovu, VRATAR NIKOLI (I21); guest lista nikoli po e-naslovu
 *  5  q z znaki % in _ je dobesedno besedilo (ne vzorec); neveljavni limit/offset/q -> 400; tuj klub/dogodek -> prazno
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 5781, JWKS_PORT = 5782;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-vstopnice-seznam";
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
      ana: zeton("ana@outly.si", uuid(4)), bor: zeton("bor@outly.si", uuid(5)), tuj: zeton("tuj@outly.si", uuid(6)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','tuj@outly.si')");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='tuj@outly.si'), 'Tuj Club', 'Maribor')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");

    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const x = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Velik dogodek", startAt: cezDan, ticketPriceCents: 1000, minAge: 0 });
    assert(x.status === 201, "dogodek brez omejitve zmogljivosti", x.body);
    const ev = x.body.id;
    const x2 = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Majhen dogodek", startAt: cezDan, ticketPriceCents: 1000, minAge: 0 });
    const evMali = x2.body.id;

    // 1005 vstopnic neposredno v bazo (API dovoli 10 na nakup in 20 nakupov/h): 1000 navadnih (ana), 5 posebnih
    const ana = (await pool.query("SELECT id FROM users WHERE email='ana@outly.si'")).rows[0].id;
    const bor = (await pool.query("SELECT id FROM users WHERE email='bor@outly.si'")).rows[0].id;
    const naroci = async (event, uporabnik, email, n, ref) => {
      await pool.query(
        `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
         SELECT $5 || lpad(g::text, 5, '0'), $1, $2, 1, 1, 1000, 1000, 'paid', $3, NOW() FROM generate_series(1, $4::int) g`, [uporabnik, event, email, n, ref]);
    };
    await naroci(ev, ana, "ana@outly.si", 1000, "ANA");
    await pool.query(`INSERT INTO tickets (order_id, event_id) SELECT o.id, o.event_id FROM orders o WHERE o.event_id = $1 ORDER BY o.id`, [ev]);
    // posebne vstopnice (po id vrsti ZADNJE: pri rezu 1000 jih stari odjemalec ne vidi): bor, gost brez racuna, guest lista
    await naroci(ev, bor, "bor@outly.si", 1, "BORX");
    await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at, guest_email, guest_terms_version, guest_terms_accepted_at)
                      VALUES ('GOSTX00001', NULL, $1, 1, 1, 1000, 1000, 'paid', 'gost.skrivni@primer.si', NOW(), 'gost.skrivni@primer.si', 'v1', NOW())`, [ev]);
    await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
                      VALUES ('REFVRNJ001', $2, $1, 1, 1, 1000, 1000, 'paid', 'ana@outly.si', NOW())`, [ev, ana]);
    await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
                      VALUES ('VOIDXXX001', $2, $1, 1, 1, 1000, 1000, 'paid', 'ana@outly.si', NOW())`, [ev, ana]);
    await pool.query(`INSERT INTO tickets (order_id, event_id) SELECT o.id, o.event_id FROM orders o WHERE o.event_id = $1 AND o.public_ref IN ('BORX00001','GOSTX00001','REFVRNJ001','VOIDXXX001') ORDER BY o.id`, [ev]);
    // guest lista: vstopnica gostitelja (ana) z orders.guest_list_id; e-naslova vstopnice guest liste odgovor nikoli ne vrne
    const gl = (await pool.query(`INSERT INTO guest_lists (event_id, host_user_id, spots) VALUES ($1, $2, 3) RETURNING id`, [ev, ana])).rows[0];
    await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at, guest_list_id)
                      VALUES ('GLISTA0001', $2, $1, 1, 1, 0, 0, 'paid', 'glista.skrivna@primer.si', NOW(), $3)`, [ev, ana, gl.id]);
    await pool.query(`INSERT INTO tickets (order_id, event_id) SELECT o.id, o.event_id FROM orders o WHERE o.public_ref = 'GLISTA0001'`);
    // stanja: ena vrnjena, ena neveljavna, 7 porabljenih (med njimi bor), prenos: ena vstopnica ane je pri boru
    await pool.query(`UPDATE tickets SET status='refunded' WHERE order_id=(SELECT id FROM orders WHERE public_ref='REFVRNJ001')`);
    await pool.query(`UPDATE tickets SET status='void' WHERE order_id=(SELECT id FROM orders WHERE public_ref='VOIDXXX001')`);
    await pool.query(`UPDATE tickets SET status='used', used_at=NOW() WHERE id IN (SELECT id FROM tickets WHERE event_id=$1 AND status='valid' ORDER BY id LIMIT 6)`, [ev]);
    await pool.query(`UPDATE tickets SET status='used', used_at=NOW() WHERE order_id=(SELECT id FROM orders WHERE public_ref='BORX00001')`);
    const skupaj = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE event_id=$1", [ev])).rows[0].n;
    const vrnjenih = 1, neveljavnih = 1, porabljenih = 7;
    const prodanih = skupaj - vrnjenih - neveljavnih;
    assert(skupaj >= 1004, `v bazi ${skupaj} vstopnic dogodka`, skupaj);

    console.log("\n# 1. Brez parametrov: golo polje, najvec 1000 (kot doslej)");
    let r = await api("GET", `/business/events/${ev}/tickets`, T.lastnik);
    assert(r.status === 200 && Array.isArray(r.body) && r.body.length === 1000, "golo polje z natanko 1000 vrsticami", { status: r.status, tip: typeof r.body, n: r.body.length });
    assert(r.body[0].id < r.body[999].id && !r.body.some(t => t.buyer_username === "bor"), "urejeno po id; posebne vstopnice na koncu so odrezane (stari odjemalec jih ne vidi)");
    const kljuci = Object.keys(r.body[0]).sort().join(",");
    assert(["id", "order_id", "event_id", "serial", "status", "qr", "public_ref", "buyer_email", "buyer_username", "holder_username", "is_vip", "payment_disputed"].every(k => k in r.body[0]), "polja vrstice so ista kot doslej", kljuci);

    console.log("\n# 2. limit/offset: ovojnica in strani");
    r = await api("GET", `/business/events/${ev}/tickets?limit=400`, T.lastnik);
    assert(r.status === 200 && !Array.isArray(r.body) && r.body.tickets.length === 400 && r.body.limit === 400 && r.body.offset === 0, "limit=400 -> ovojnica z 400 vrsticami", Object.keys(r.body));
    assert(r.body.total === skupaj && r.body.has_more === true && r.body.next_offset === 400, "total = vse, has_more, next_offset = 400", { total: r.body.total, has_more: r.body.has_more, next: r.body.next_offset });
    const videni = new Set(), idji = [];
    let off = 0, strani = 0, hasMore = true;
    while (hasMore && strani < 20) {
      const s = await api("GET", `/business/events/${ev}/tickets?limit=300&offset=${off}`, T.lastnik);
      assert(s.status === 200, `stran offset=${off}`, s.status);
      for (const t of s.body.tickets) { videni.add(t.id); idji.push(t.id); }
      hasMore = s.body.has_more; off = s.body.next_offset; strani++;
      if (!hasMore) assert(s.body.next_offset === null, "zadnja stran: next_offset null");
    }
    assert(videni.size === skupaj && idji.length === skupaj, `strani skupaj dajo vseh ${skupaj} vstopnic brez podvojitev`, { videni: videni.size, vrstic: idji.length });
    assert(idji.every((v, i) => i === 0 || idji[i - 1] < v), "vrstni red po id prek strani");
    assert(strani === Math.ceil(skupaj / 300), `strani: ${strani}`);
    r = await api("GET", `/business/events/${ev}/tickets?offset=1000`, T.lastnik);
    assert(r.status === 200 && r.body.limit === 200 && r.body.tickets.length === skupaj - 1000 && r.body.has_more === false, "samo offset: privzeti limit 200; vrne ostanek, ki ga stari rez ni videl", { n: r.body.tickets && r.body.tickets.length, limit: r.body.limit });
    assert(r.body.tickets.some(t => t.buyer_username === "bor") && r.body.tickets.some(t => t.buyer_username === "Guest"), "ostanek vsebuje bora in gosta");
    r = await api("GET", `/business/events/${ev}/tickets?limit=1000&offset=0`, T.lastnik);
    assert(r.status === 200 && r.body.tickets.length === 1000 && r.body.has_more === true, "limit=1000: natanko 1000 in has_more");
    r = await api("GET", `/business/events/${ev}/tickets?offset=99999`, T.lastnik);
    assert(r.status === 200 && r.body.tickets.length === 0 && r.body.has_more === false && r.body.next_offset === null && r.body.total === skupaj, "offset cez konec: prazno, total ostane");

    console.log("\n# 3. counts so neodvisni od reza");
    r = await api("GET", `/business/events/${ev}/tickets?limit=0`, T.lastnik);
    assert(r.status === 200 && r.body.tickets.length === 0 && r.body.has_more === true, "limit=0: samo stevci", { n: r.body.tickets && r.body.tickets.length });
    const c = r.body.counts;
    assert(c.all === skupaj && c.sold === prodanih && c.checked_in === porabljenih && c.expected === prodanih - porabljenih && c.refunded === vrnjenih && c.void === neveljavnih,
      "counts: all, sold = valid+used, checked_in, expected = valid, refunded, void", c);
    for (const [ime, url] of [["limit=10", "limit=10"], ["offset=500&limit=5", "offset=500&limit=5"], ["q=ana", "q=ana"]]) {
      const z = await api("GET", `/business/events/${ev}/tickets?${url}`, T.lastnik);
      assert(JSON.stringify(z.body.counts) === JSON.stringify(c), `counts enaki pri ${ime}`);
    }
    r = await api("GET", `/business/events/${evMali}/tickets?limit=50`, T.lastnik);
    assert(r.status === 200 && r.body.tickets.length === 0 && r.body.counts.all === 0 && r.body.counts.sold === 0 && r.body.total === 0 && r.body.has_more === false, "dogodek brez vstopnic: ničle", r.body);

    console.log("\n# 4. q: kar vloga sme videti");
    const iskanje = (zt, q, dod = "") => api("GET", `/business/events/${ev}/tickets?q=${encodeURIComponent(q)}${dod}`, zt);
    r = await iskanje(T.lastnik, "BORX");
    assert(r.status === 200 && r.body.tickets.length === 1 && r.body.total === 1 && r.body.tickets[0].buyer_username === "bor", "q po public_ref (lastnik): najde vstopnico izven prvih 1000", r.body.tickets);
    const serial = r.body.tickets[0].serial;
    r = await iskanje(T.lastnik, serial.slice(0, 13));
    assert(r.status === 200 && r.body.tickets.length === 1 && r.body.tickets[0].serial === serial, "q po zacetku serijske stevilke", r.body.total);
    r = await iskanje(T.vratar, "bor");
    assert(r.status === 200 && r.body.tickets.length === 1 && r.body.tickets[0].holder_username === "bor" && !("buyer_email" in r.body.tickets[0]), "vratar: q po uporabniskem imenu, brez e-naslova v vrstici", r.body.tickets);
    r = await iskanje(T.vratar, "bor@outly.si");
    assert(r.status === 200 && r.body.total === 0 && r.body.tickets.length === 0, "vratar: q po e-naslovu NE najde nicesar (I21)", r.body.total);
    r = await iskanje(T.vratar, "outly.si");
    assert(r.status === 200 && r.body.total === 0, "vratar: delen e-naslov tudi ne", r.body.total);
    r = await iskanje(T.vratar, "skrivni");
    assert(r.status === 200 && r.body.total === 0, "vratar: e-naslov gosta brez racuna ne", r.body.total);
    for (const kdo of ["lastnik", "manager"]) {
      r = await iskanje(T[kdo], "bor@outly.si");
      assert(r.status === 200 && r.body.total === 1 && r.body.tickets[0].buyer_email === "bor@outly.si", `${kdo}: q po e-naslovu kupca`, r.body.total);
      r = await iskanje(T[kdo], "gost.skrivni@");
      assert(r.status === 200 && r.body.total === 1 && r.body.tickets[0].public_ref === "GOSTX00001", `${kdo}: e-naslov gosta brez racuna (viden lastniku/managerju kot doslej)`, r.body.total);
      r = await iskanje(T[kdo], "BOR@OUTLY");
      assert(r.status === 200 && r.body.total === 1, `${kdo}: brez razlike velikosti`, r.body.total);
    }
    r = await iskanje(T.vratar, "guest");
    assert(r.status === 200 && r.body.total === 1 && r.body.tickets[0].public_ref === "GOSTX00001", "vratar: »Guest« (ime gosta, ki ga vidi) najde gostujoce naročilo", r.body.total);
    r = await iskanje(T.lastnik, "glista.skrivna");
    assert(r.status === 200 && r.body.total === 0, "guest lista: e-naslova NIKOLI ne iscemo (odgovor ga ne vrne nobeni vlogi)", r.body.total);
    r = await iskanje(T.lastnik, "GLISTA0001");
    assert(r.status === 200 && r.body.total === 1 && !("buyer_email" in r.body.tickets[0]) && r.body.tickets[0].is_guest_list === true, "guest lista: po public_ref najdemo, vrstica brez e-naslova", r.body.tickets);
    r = await iskanje(T.lastnik, "ana", "&limit=5&offset=10");
    assert(r.status === 200 && r.body.tickets.length === 5 && r.body.total > 1000 && r.body.has_more === true && r.body.next_offset === 15, "q + limit + offset: total = zadetki iskanja", { n: r.body.tickets.length, total: r.body.total });
    r = await iskanje(T.lastnik, "ni-takega-imena");
    assert(r.status === 200 && r.body.total === 0 && r.body.tickets.length === 0 && r.body.counts.all === skupaj, "brez zadetkov: total 0, counts ostanejo", r.body.counts);
    r = await api("GET", `/business/events/${ev}/tickets?q=`, T.lastnik);
    assert(r.status === 200 && r.body.total === skupaj && r.body.tickets.length === 200, "prazen q = brez filtra (ovojnica)", r.body.total);
    r = await api("GET", `/business/events/${ev}/tickets?q=%20%20bor%20`, T.lastnik);
    assert(r.status === 200 && r.body.total >= 1, "q se obreze (presledki)", r.body.total);

    console.log("\n# 5. Dobesedno besedilo, 400, tuj klub");
    // Nobena vrednost ne vsebuje teh znakov: ce bi bili vzorec (% = vse, _ = en znak), bi q vrnil zadetke.
    for (const q of ["%", "_", "b_r", "bo%", "\\", "a\\"]) {
      r = await iskanje(T.lastnik, q);
      assert(r.status === 200 && r.body.total === 0 && r.body.tickets.length === 0, `q=${JSON.stringify(q)}: dobesedno besedilo, ne vzorec (0 zadetkov)`, { status: r.status, total: r.body.total });
    }
    for (const [url, koda] of [["limit=-1", "invalid_limit"], ["limit=1001", "invalid_limit"], ["limit=abc", "invalid_limit"], ["limit=", "invalid_limit"], ["limit=1.5", "invalid_limit"],
      ["limit=1&limit=2", "invalid_limit"], ["offset=-5", "invalid_offset"], ["offset=x", "invalid_offset"], ["offset=99999999999", "invalid_offset"],
      ["q=" + "a".repeat(65), "invalid_q"], ["q=a&q=b", "invalid_q"], ["q[x]=1", "invalid_q"]]) {
      r = await api("GET", `/business/events/${ev}/tickets?${url}`, T.lastnik);
      assert(r.status === 400 && r.body && r.body.error === koda, `${url.slice(0, 30)} -> 400 ${koda}`, { status: r.status, body: r.body });
    }
    r = await iskanje(T.lastnik, "a".repeat(64));
    assert(r.status === 200, "q z 64 znaki je se v redu", r.status);
    r = await api("GET", `/business/events/${ev}/tickets?limit=10`, T.tuj);
    assert(r.status === 403 || r.status === 404 || (r.status === 200 && r.body.counts.all === 0 && r.body.tickets.length === 0), "lastnik DRUGEGA kluba ne vidi vstopnic (vrsta se filtrira po klubu)", { status: r.status, body: r.body && r.body.counts });
    r = await api("GET", `/business/events/${ev}/tickets?limit=10&q=ana`, T.tuj);
    assert(!(r.body && r.body.tickets && r.body.tickets.length) && !(r.body && r.body.total), "isto z iskanjem: nic", r.body);
    r = await api("GET", `/business/events/${ev}/tickets?limit=10`, T.ana);
    assert(r.status === 403 || r.status === 404, "navaden uporabnik: zavrnjen", r.status);
    r = await api("GET", `/business/events/${ev}/tickets?limit=10`);
    assert(r.status === 401, "brez zetona: 401", r.status);
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    srv.kill(); jwksServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + log.split("\n").slice(-40).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
