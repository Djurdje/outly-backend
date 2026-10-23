#!/usr/bin/env node
/**
 * Okno prodaje »od – do« v PATCH /events/:id (#327, »PR A« nacrta admin panela 23. 10. 2026). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_prodaja_okno.js
 * Stolpca events.sales_open_at / sales_close_at in omejitev events_sales_window_chk sta od migracije 002, nakup (napakaProdaje) in on_sale ju upostevata;
 * nova je samo nastavitev prek PATCH-a. Vzorec kot test_prodaja_pavza.js: lokalni JWKS, lazni placilni streznik (samo ustvarjanje seje), svoj port, TRUNCATE.
 *
 *  O1  okno v prihodnosti: PATCH 200, vrednosti v GET /admin/api/events/:id; vstopnice, gost in VIP miza -> 409 »not opened yet«; on_sale false (GET /events/:id, /events)
 *  O2  okno v preteklosti (zaprto): vse tri poti -> 409 »closed«; on_sale false
 *  O3  odprto okno: on_sale true, vse tri poti 201 (pozitivna kontrola); availability in cena se ne spremenita
 *  O4  neveljavno: zapre <= odpre (obe polji, samo eno proti obstojecemu drugemu, enaka casa) -> 400 invalid_sales_window in NIC ni spremenjeno;
 *      slab zapis (niz brez casa, brez obmocja, stevilo, prazen niz, nesmiselen datum) -> 400
 *  O5  null pobrise (eno ali obe polji); snake_case imena delujejo
 *  O6  vloge: manager 200, vratar 403, tuj lastnik 403, navaden uporabnik 403, brez zetona 401; po 403 vrednosti nespremenjene
 *  O8  javni GET /events (tudi lite) in /events/:id vrnejo sales_open_at / sales_close_at (ISO ali null); publish_at ne
 *  O7  dnevnik: admin sprememba = vrstica admin_dejanja (prej/potem samo spremenjeni polji); sprememba lastnika vrstice NE ustvari; ista vrednost vrstice ne ustvari
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 5841, JWKS_PORT = 5842, PLACILA_PORT = 5843;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-okno";
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

let ipSt = 0;
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.78.${(++ipSt >> 8) & 255}.${(ipSt & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

// Lazni placilni streznik: samo ustvari checkout sejo (pozitivna kontrola nakupa); expire sprejme.
let nSej = 0;
const placilaServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (s, o) => { res.writeHead(s, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const id = "cs_test_o" + (++nSej);
      return odg(200, { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        amount_total: Number(p["line_items[0][quantity]"]) * Number(p["line_items[0][price_data][unit_amount]"]), currency: p["line_items[0][price_data][currency]"],
        livemode: false, metadata: { order_id: p["metadata[order_id]"] }, client_reference_id: p.client_reference_id, expires_at: Number(p.expires_at), payment_intent: null });
    }
    if (req.method === "POST" && /\/expire$/.test(u)) return odg(200, { id: u.split("/")[4], object: "checkout.session", status: "expired" });
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni streznik: neznana pot " + req.method + " " + u } });
  });
});

let srv = null, log = "";
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, admin_dejanja, vracila, stripe_events, club_event_notifications, club_follows, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, event_tables, club_tables, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => placilaServer.listen(PLACILA_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_test_okno", STRIPE_API_BASE: `http://127.0.0.1:${PLACILA_PORT}`, STRIPE_POSPRAVI_MS: "0", STRIPE_PREKLIC_PO_S: "1",
    APP_URL: "https://outly.test", TEST_PLACILA: "", GOST_NAKUP_TEST: "1", GOST_NAKUP_NA_URO: "1000", REZERVACIJE_CISCENJE_MS: "0",
    VRACILA_TICK_MS: "0", VRACILA_SWEEP_MS: "0", JAVNI_PREDPOMNILNIK_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 60; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), tuj: zeton("tuj@outly.si", uuid(2)), admin: zeton("admin@outly.si", uuid(3)),
      ana: zeton("ana@outly.si", uuid(4)), bor: zeton("bor@outly.si", uuid(5)), cene: zeton("cene@outly.si", uuid(6)), dana: zeton("dana@outly.si", uuid(7)),
      vratar: zeton("vratar@outly.si", uuid(8)), manager: zeton("manager@outly.si", uuid(9)), erik: zeton("erik@outly.si", uuid(10)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','tuj@outly.si')");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET date_of_birth='1990-01-01'");
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, stripe_account_id, stripe_charges_enabled)
                      VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana', 'acct_test1', TRUE)`);
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='tuj@outly.si'), 'Tuj Club', 'Maribor')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman'), (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1, 'A1', 10, 10, 10, 10, 4, 20000), (1, 'A2', 30, 10, 10, 10, 4, 20000), (1, 'A3', 50, 10, 10, 10, 4, 20000)");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const E = (await pool.query("INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age, vip_enabled) VALUES (1,'Okno noc',$1,'published',1500,100,0,TRUE) RETURNING id", [cezDan])).rows[0].id;

    const ure = (h) => new Date(Date.now() + h * 3600 * 1000).toISOString();
    const okno = async () => { const x = (await pool.query("SELECT sales_open_at, sales_close_at FROM events WHERE id=$1", [E])).rows[0]; return { od: x.sales_open_at ? x.sales_open_at.toISOString() : null, do: x.sales_close_at ? x.sales_close_at.toISOString() : null }; };
    const dnevnik = async () => (await pool.query("SELECT dejanje, prej, potem FROM admin_dejanja WHERE cilj_tip='event' AND cilj_id=$1 ORDER BY id", [String(E)])).rows;
    const stNarocil = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [E])).rows[0].n;
    const kupiV = (tok) => api("POST", `/events/${E}/orders`, tok, { quantity: 1 });
    const kupiG = (email) => api("POST", `/guest/events/${E}/orders`, null, { email, quantity: 1, accept_terms: true, terms_version: "2026-10-01" });
    const kupiM = (tok, miza) => api("POST", `/events/${E}/tables/${miza}/orders`, tok, {});
    const javni = async () => (await api("GET", `/events/${E}`)).body;
    const NEODPRTA = /not opened yet/i, ZAPRTA = /closed/i;

    console.log("\n# O1: okno v prihodnosti (lastnik)");
    const od1 = ure(1), do1 = ure(3);
    let r = await api("PATCH", `/events/${E}`, T.lastnik, { salesOpenAt: od1, salesCloseAt: do1 });
    assert(r.status === 200 && new Date(r.body.sales_open_at).getTime() === new Date(od1).getTime() && new Date(r.body.sales_close_at).getTime() === new Date(do1).getTime(), "PATCH { salesOpenAt, salesCloseAt } -> 200, polji v odgovoru", r.body);
    r = await api("GET", `/admin/api/events/${E}`, T.admin);
    assert(r.status === 200 && r.body.event.sales_open_at === od1 && r.body.event.sales_close_at === do1, "GET /admin/api/events/:id vrne obe vrednosti", r.body.event);
    let j = await javni();
    assert(j.on_sale === false && j.availability === "available" && j.ticket_price_cents === 1500, "GET /events/:id: on_sale false, availability in cena nespremenjena", j);
    r = await api("GET", "/events");
    assert(r.status === 200 && r.body.length === 1 && r.body[0].on_sale === false, "GET /events: on_sale false", r.body);
    let k = await kupiV(T.ana);
    assert(k.status === 409 && NEODPRTA.test(k.body), "vstopnice pred odprtjem -> 409 »not opened yet«", k);
    k = await kupiG("gost1@example.com");
    assert(k.status === 409 && NEODPRTA.test(k.body), "gost pred odprtjem -> 409", k);
    k = await kupiM(T.bor, 1);
    assert(k.status === 409 && NEODPRTA.test(k.body), "VIP miza pred odprtjem -> 409", k);
    assert(await stNarocil() === 0, "zavrnjeni nakupi niso ustvarili narocil");

    console.log("\n# O2: okno v preteklosti (zaprto)");
    const od2 = ure(-3), do2 = ure(-1);
    r = await api("PATCH", `/events/${E}`, T.lastnik, { salesOpenAt: od2, salesCloseAt: do2 });
    assert(r.status === 200, "PATCH okno v preteklosti -> 200", r.body);
    k = await kupiV(T.ana);
    assert(k.status === 409 && ZAPRTA.test(k.body) && !NEODPRTA.test(k.body), "vstopnice po zaprtju -> 409 »closed«", k);
    k = await kupiG("gost1@example.com");
    assert(k.status === 409 && ZAPRTA.test(k.body), "gost po zaprtju -> 409", k);
    k = await kupiM(T.bor, 1);
    assert(k.status === 409 && ZAPRTA.test(k.body), "VIP miza po zaprtju -> 409", k);
    j = await javni();
    assert(j.on_sale === false && j.availability === "available", "on_sale false po zaprtju", j);
    assert(await stNarocil() === 0, "po zaprtju ni narocil");

    console.log("\n# O3: odprto okno (pozitivna kontrola)");
    r = await api("PATCH", `/events/${E}`, T.lastnik, { salesOpenAt: ure(-1), salesCloseAt: ure(2) });
    assert(r.status === 200, "PATCH odprto okno -> 200", r.body);
    j = await javni();
    assert(j.on_sale === true && j.availability === "available" && j.ticket_price_cents === 1500, "on_sale true, availability/cena nespremenjena", j);
    k = await kupiV(T.ana);
    assert(k.status === 201 && k.body.checkout_url, "vstopnice v oknu -> 201", k);
    k = await kupiG("gost1@example.com");
    assert(k.status === 201 && k.body.checkout_url, "gost v oknu -> 201", k);
    k = await kupiM(T.bor, 1);
    assert(k.status === 201 && k.body.checkout_url, "VIP miza v oknu -> 201", k);

    console.log("\n# O4: neveljavno okno -> 400, nic spremenjeno");
    const pred = await okno();
    const neveljavno = [
      ["zapre pred odprtjem (obe polji)", { salesOpenAt: ure(2), salesCloseAt: ure(1) }],
      ["enaka casa", { salesOpenAt: "2030-01-01T10:00:00.000Z", salesCloseAt: "2030-01-01T10:00:00.000Z" }],
      ["samo zapre, pred obstojecim odprtjem", { salesCloseAt: ure(-5) }],
      ["samo odpre, po obstojecem zaprtju", { salesOpenAt: ure(10) }],
      ["snake_case, obrnjeno", { sales_open_at: ure(2), sales_close_at: ure(1) }],
    ];
    for (const [ime, telo] of neveljavno) {
      r = await api("PATCH", `/events/${E}`, T.lastnik, telo);
      assert(r.status === 400 && r.body && r.body.error === "invalid_sales_window" && typeof r.body.message === "string", `${ime} -> 400 invalid_sales_window`, r);
    }
    r = await api("PATCH", `/events/${E}`, T.admin, { salesOpenAt: ure(2), salesCloseAt: ure(1) });
    assert(r.status === 400 && r.body.error === "invalid_sales_window", "admin: obrnjeno okno -> 400 invalid_sales_window", r);
    for (const [ime, vrednost] of [["niz brez casa", "danes"], ["samo datum", "2030-01-01"], ["cas brez obmocja", "2030-01-01T10:00:00"], ["stevilo", 1893456000000],
      ["prazen niz", ""], ["nesmiselen datum", "2030-13-45T10:00:00Z"], ["31. februar", "2026-02-31T10:00Z"], ["29. februar v navadnem letu", "2027-02-29T10:00:00Z"], ["leto 0001", "0001-01-01T00:00:00Z"], ["leto 0000", "0000-06-01T00:00:00Z"], ["leto 2101", "2101-01-01T00:00:00Z"], ["ura 24", "2030-01-01T24:00:00Z"], ["boolean", true], ["objekt", {}]]) {
      r = await api("PATCH", `/events/${E}`, T.lastnik, { salesCloseAt: vrednost });
      assert(r.status === 400 && !(r.body && r.body.error === "invalid_sales_window"), `salesCloseAt: ${ime} -> 400`, r);
      r = await api("PATCH", `/events/${E}`, T.lastnik, { salesOpenAt: vrednost });
      assert(r.status === 400, `salesOpenAt: ${ime} -> 400`, r);
    }
    assert(JSON.stringify(await okno()) === JSON.stringify(pred), "po vseh zavrnitvah okno ni spremenjeno", { pred, zdaj: await okno() });
    assert((await dnevnik()).length === 0, "zavrnjene spremembe niso zapisale vrstice v admin_dejanja");

    console.log("\n# O5: null pobrise, snake_case deluje");
    r = await api("PATCH", `/events/${E}`, T.lastnik, { salesOpenAt: null });
    assert(r.status === 200 && r.body.sales_open_at === null && r.body.sales_close_at !== null, "salesOpenAt: null pobrise samo odprtje", r.body);
    const dvaH = ure(2);
    r = await api("PATCH", `/events/${E}`, T.lastnik, { sales_close_at: dvaH });
    assert(r.status === 200 && new Date(r.body.sales_close_at).getTime() === new Date(dvaH).getTime(), "sales_close_at (snake_case) deluje; zapre brez odprtja je veljavno", r.body);
    r = await api("PATCH", `/events/${E}`, T.lastnik, { salesCloseAt: "2028-02-29T10:00:00+01:00" });
    assert(r.status === 200 && r.body.sales_close_at === "2028-02-29T09:00:00.000Z", "29. 2. v prestopnem letu z odmikom +01:00 -> 200, shranjeno v UTC", r.body);
    r = await api("PATCH", `/events/${E}`, T.lastnik, { salesOpenAt: null, salesCloseAt: null });
    assert(r.status === 200 && r.body.sales_open_at === null && r.body.sales_close_at === null, "obe null -> brez omejitve", r.body);
    assert(JSON.stringify(await okno()) === JSON.stringify({ od: null, do: null }), "baza: obe polji NULL", await okno());
    j = await javni();
    assert(j.on_sale === true, "on_sale true brez okna", j);
    k = await kupiV(T.cene);
    assert(k.status === 201, "nakup brez okna -> 201", k);
    r = await api("PATCH", `/events/${E}`, T.lastnik, { title: "Okno noc 2" });
    assert(r.status === 200 && r.body.sales_open_at === null, "PATCH brez oken ju ne spremeni", r.body);

    console.log("\n# O6: vloge");
    const stanje = { salesOpenAt: ure(5), salesCloseAt: ure(6) };
    r = await api("PATCH", `/events/${E}`, T.manager, stanje);
    assert(r.status === 200 && r.body.sales_open_at, "manager kluba -> 200", r);
    const po200 = await okno();
    r = await api("PATCH", `/events/${E}`, T.vratar, { salesOpenAt: null, salesCloseAt: null });
    assert(r.status === 403, "vratar kluba -> 403", r);
    r = await api("PATCH", `/events/${E}`, T.tuj, { salesOpenAt: null, salesCloseAt: null });
    assert(r.status === 403, "tuj lastnik -> 403", r);
    r = await api("PATCH", `/events/${E}`, T.erik, { salesOpenAt: null, salesCloseAt: null });
    assert(r.status === 403, "navaden uporabnik -> 403", r);
    r = await api("PATCH", `/events/${E}`, null, { salesOpenAt: null, salesCloseAt: null });
    assert(r.status === 401, "brez zetona -> 401", r);
    assert(JSON.stringify(await okno()) === JSON.stringify(po200), "po zavrnitvah okno nespremenjeno", { po200, zdaj: await okno() });

    console.log("\n# O7: dnevnik admin dejanj");
    assert((await dnevnik()).length === 0, "do sedaj (lastnik, manager) nobene vrstice v dnevniku", await dnevnik());
    const odA = ure(20), doA = ure(22);
    r = await api("PATCH", `/events/${E}`, T.admin, { salesOpenAt: odA, salesCloseAt: doA });
    assert(r.status === 200, "admin nastavi okno -> 200", r.body);
    let dn = await dnevnik();
    assert(dn.length === 1 && dn[0].dejanje === "event.update", "ena vrstica event.update", dn);
    assert(dn[0] && Object.keys(dn[0].potem).sort().join() === "sales_close_at,sales_open_at" && dn[0].potem.sales_open_at === odA && dn[0].potem.sales_close_at === doA
      && dn[0].prej.sales_open_at === po200.od && dn[0].prej.sales_close_at === po200.do, "prej/potem samo obe spremenjeni polji (ISO)", dn[0]);
    r = await api("PATCH", `/events/${E}`, T.admin, { salesOpenAt: odA, salesCloseAt: doA });
    assert(r.status === 200 && (await dnevnik()).length === 1, "ista vrednost ponovno -> 200, brez nove vrstice", await dnevnik());
    r = await api("PATCH", `/events/${E}`, T.admin, { salesCloseAt: null });
    dn = await dnevnik();
    assert(r.status === 200 && dn.length === 2 && JSON.stringify(dn[1].potem) === '{"sales_close_at":null}' && dn[1].prej.sales_close_at === doA, "brisanje zapre -> druga vrstica (prej ISO, potem null)", dn);
    r = await api("GET", `/admin/api/audit?target_type=event&target_id=${E}`, T.admin);
    assert(r.status === 200 && JSON.stringify(r.body).includes("sales_open_at"), "GET /admin/api/audit kaze spremembo okna", r.body);
    console.log("\n# O8: okno v javnih odgovorih (GET /events, GET /events/:id)");
    const od8 = ure(5), do8 = ure(7);
    await pool.query("UPDATE events SET sales_open_at=$2, sales_close_at=$3 WHERE id=$1", [E, od8, do8]);
    j = await javni();
    assert(j.sales_open_at === od8 && j.sales_close_at === do8, "GET /events/:id vrne sales_open_at in sales_close_at (ISO)", { o: j.sales_open_at, z: j.sales_close_at });
    r = await api("GET", "/events");
    assert(r.status === 200 && r.body[0].sales_open_at === od8 && r.body[0].sales_close_at === do8, "GET /events vrne oba casa", r.body[0]);
    r = await api("GET", "/events?lite=true");
    assert(r.status === 200 && r.body[0].sales_open_at === od8 && r.body[0].sales_close_at === do8, "GET /events?lite=true vrne oba casa", r.body[0]);
    r = await api("GET", `/events/${E}`, T.ana);
    assert(r.status === 200 && r.body.sales_open_at === od8, "prijavljen uporabnik dobi isto", r.body);
    await pool.query("UPDATE events SET sales_open_at=NULL, sales_close_at=NULL WHERE id=$1", [E]);
    j = await javni();
    assert(j.sales_open_at === null && j.sales_close_at === null, "GET /events/:id: oba null, ko nista nastavljena", { o: j.sales_open_at, z: j.sales_close_at });
    r = await api("GET", "/events");
    assert(r.body[0].sales_open_at === null && r.body[0].sales_close_at === null, "GET /events: oba null, ko nista nastavljena", r.body[0]);
    assert(!("publish_at" in j) && !("publishAt" in j), "publish_at se javno ne vraca", Object.keys(j));

    assert(!/Server error|TypeError|ReferenceError/.test(log), "dnevnik streznika brez napak", log.split("\n").filter(l => /Server error|Error/.test(l)).slice(0, 3));
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    srv.kill(); jwksServer.close(); placilaServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + log.split("\n").slice(-60).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
