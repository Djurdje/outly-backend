#!/usr/bin/env node
/**
 * Prenos vstopnice prijatelju BREZ racuna (migracija 034, invarianta I23 + I7/I8). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_prenos_gost.js
 * Vzorec kot test_gost.js: lokalni JWKS, lazni Resend (RESEND_BASE_URL), trije backendi na svojih portih:
 *   A = privzeto stikalo (PRENOS_BREZ_RACUNA prazno: samo admin), B = PRENOS_BREZ_RACUNA=vsi, C = vsi + nizke meje zlorabe.
 *
 *   1  stikalo: can_transfer_to_guest v GET/PATCH /me; stari odjemalec (brez allow_guest) 404 kot prej; izklopljeno 403; admin dela
 *   2  starost: gost brez age_confirmed 400 (min_age), s potrditvijo 200; paket (VIP) = max(min_age, 18); prenos na racun: potrditev brez
 *      datuma rojstva dovoli, znan mladoletnik 403, stari odjemalec brez potrditve kot doslej
 *   3  racun z istim e-naslovom: enoten odgovor, prenos na racun, brez maila; nepotrjen racun = gost
 *   4  gost: serial zamenjan, star QR ne velja, v bazi hash zetona, posiljatelj zetona ne dobi, mail enkrat (CID slika + PDF, brez e-naslovov)
 *   5  GET /guest/ticket: oblika, 404 enoten, veljaven zeton nikoli 429, sken gostove kode (en vstop)
 *   6  pogledi: kupec (prenesena, brez e-naslova), lastnik/vratar (Guest, brez e-naslova), scan-list, /me/tickets kupca brez
 *   7  prevzem v racun: potrjen e-naslov -> vstopnica njegova, zeton preklican, serial isti; nepotrjen se ne prevzame
 *   8  mail: napaka Resenda -> pospravljalec poslje (enkrat); hramba: konec dogodka + 30 dni anonimizacija
 *   9  zloraba: meja na posiljatelja in na naslov (429), hkratni prenos iste vstopnice (en uspe)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3197, PORT_B = 3198, PORT_C = 3199, PORT_D = 3200, PORT_E = 3201, JWKS_PORT = 3954, RESEND_PORT = 3955;
const A = `http://127.0.0.1:${PORT_A}`, B = `http://127.0.0.1:${PORT_B}`, C = `http://127.0.0.1:${PORT_C}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-prenos-gost";
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
let xff = 0;   // omejevalnik prenosov (30/h/IP) je v bazi: vsak zahtevek z druge »IP« (trust proxy 1), sicer bi test sam sebe omejil
async function zahtevek(baza, method, path, token, body, glave = {}) {
  const r = await fetch(baza + path, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.9.${Math.floor(++xff / 250)}.${xff % 250 + 1}`, ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, headers: r.headers, tekst: t };
}
const api = (m, p, t, b, g) => zahtevek(A, m, p, t, b, g);
const apiB = (m, p, t, b, g) => zahtevek(B, m, p, t, b, g);
const apiC = (m, p, t, b, g) => zahtevek(C, m, p, t, b, g);
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 6000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(100); } return false; }

// ---------- lazni Resend ----------
const R = { poslano: [], napaka: false };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      if (R.napaka) { res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub: zavrnjeno", statusCode: 422 })); }
      const m = JSON.parse(d);
      R.poslano.push(m);
      res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + R.poslano.length }));
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const poslanoNa = (email) => R.poslano.filter(m => m.to === email || (Array.isArray(m.to) && m.to.includes(email)));
const zetonIzMaila = (m) => { const x = /\/app\/guest\/ticket#t=([A-Za-z0-9_-]{43})/.exec(m.html || ""); return x ? x[1] : null; };

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    TEST_PLACILA: "", GOST_PREVZEM_MS: "0", RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>",
    GOST_POSTA_PONOVI_MS: "500", GOST_POSTA_PREMOR_MS: "400", GOST_POSTA_TIMEOUT_MS: "1500", REZERVACIJE_CISCENJE_MS: "1000", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const s = { srv, log: "" };
  srv.stdout.on("data", d => s.log += d); srv.stderr.on("data", d => s.log += d);
  return s;
}
async function cakajStreznik(baza) { for (let i = 0; i < 80; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }
const PNG_PODPIS = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
const hash = (z) => crypto.createHash("sha256").update(z).digest("hex");

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  const poslanoOb = async (tid) => (await pool.query("SELECT holder_guest_mail_sent_at AS t FROM tickets WHERE id=$1", [tid])).rows[0].t;
  const dodatni = [];
  const a = zagon(PORT_A, {});
  const b = zagon(PORT_B, { PRENOS_BREZ_RACUNA: "vsi", GOST_PRENOS_NA_DAN: "1000", GOST_PRENOS_NA_NASLOV: "1000", GOST_NEUSPESNI_NA_URO: "3" });
  const c = zagon(PORT_C, { PRENOS_BREZ_RACUNA: "vsi", GOST_PRENOS_NA_DAN: "3", GOST_PRENOS_NA_NASLOV: "2" });
  await cakajStreznik(A); await cakajStreznik(B); await cakajStreznik(C);

  try {
    const emaili = { lastnik: "lastnik@outly.si", vratar: "vratar@outly.si", admin: "admin@outly.si", kupec: "kupec@outly.si", kupec2: "kupec2@outly.si", kupec3: "kupec3@outly.si", kupec4: "kupec4@outly.si",
      racun: "racun@outly.si", brezdatuma: "brezdatuma@outly.si", mladi: "mladi@outly.si", nepotrjen: "nepotrjen@outly.si", novi: "novi@outly.si" };
    const T = {}; let n = 0;
    for (const [k, e] of Object.entries(emaili)) T[k] = zeton(e, uuid(++n));
    for (const k of Object.keys(T)) { const r = await apiB("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '25 years')::date WHERE email IN ('kupec@outly.si','kupec2@outly.si','kupec3@outly.si','kupec4@outly.si','racun@outly.si','admin@outly.si')");
    await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '17 years')::date WHERE email='mladi@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, address, city, contact_email) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Trg 1', 'Ljubljana', 'info@pure.test')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman')");
    const dogodek = async (naslov, minAge, vip = false) => (await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, status, ticket_price_cents, capacity, min_age, vip_enabled)
       VALUES (1,$1,'https://example.com/p.jpg', NOW() + INTERVAL '2 days', 'published', 1500, 200, $2, $3) RETURNING id`, [naslov, minAge, vip])).rows[0].id;
    const E0 = await dogodek("Prenos Noc", 0), E18 = await dogodek("Prenos 18+", 18), E21 = await dogodek("Prenos VIP 21+", 21, true), EV = await dogodek("Prenos VIP", 0, true);
    const kupi = async (tok, ev, kol = 1) => { const r = await apiB("POST", `/events/${ev}/orders`, tok, { quantity: kol }); if (r.status !== 201) console.log("kupi", r.status, r.body); return r.body.tickets; };
    const vstopnica = async (id) => (await pool.query("SELECT serial, holder_user_id, holder_is_guest, holder_guest_email, status FROM tickets WHERE id=$1", [id])).rows[0];
    const prenesi = (baza, id, tok, telo) => zahtevek(baza, "POST", `/tickets/${id}/transfer`, tok, telo);

    // ============================================================
    console.log("\n# 1. Stikalo in stari odjemalec");
    let r = await api("GET", "/me", T.kupec);
    assert(r.status === 200 && r.body.can_transfer_to_guest === false, "A (stikalo prazno): navaden uporabnik can_transfer_to_guest = false", r.body.can_transfer_to_guest);
    r = await api("GET", "/me", T.admin);
    assert(r.body.can_transfer_to_guest === true, "A: admin can_transfer_to_guest = true", r.body.can_transfer_to_guest);
    r = await apiB("GET", "/me", T.kupec);
    assert(r.body.can_transfer_to_guest === true, "B (PRENOS_BREZ_RACUNA=vsi): navaden uporabnik true", r.body.can_transfer_to_guest);
    r = await api("PATCH", "/me", T.kupec, { country: "SI" });
    assert(r.status === 200 && r.body.can_transfer_to_guest === false, "PATCH /me vrne tudi can_transfer_to_guest", r.body);
    let vst = await kupi(T.kupec, E0, 8);
    const [t1, t2, t3, t4, t5, t6, t7, t8] = vst;
    r = await api("POST", `/tickets/${t1.id}/transfer`, T.kupec, { email: "tujec@example.com" });
    assert(r.status === 404 && /No Outly account/.test(r.body), "stari odjemalec (brez allow_guest): 404 »No Outly account« kot prej", r);
    r = await api("POST", `/tickets/${t1.id}/transfer`, T.kupec, { email: "tujec@example.com", allow_guest: true });
    assert(r.status === 403 && r.body.error === "guest_transfer_disabled" && r.body.message, "A, stikalo izklopljeno, navaden uporabnik + allow_guest: 403 guest_transfer_disabled", r.body);
    let v = await vstopnica(t1.id);
    assert(v.holder_is_guest === false && v.holder_user_id === null && v.serial === t1.serial, "zavrnjen prenos ne spremeni vstopnice");
    r = await api("POST", `/tickets/${t1.id}/transfer`, T.kupec, { email: "tujec@example.com", allow_guest: "true" });
    assert(r.status === 404, "allow_guest mora biti boolean true (niz 'true' = stari odjemalec -> 404)", r.status);
    r = await api("POST", `/tickets/${t1.id}/transfer`, T.kupec, { email: "tujec@example.com", allow_guest: false });
    assert(r.status === 404, "allow_guest: false = stari odjemalec -> 404", r.status);
    r = await apiB("POST", `/tickets/${t1.id}/transfer`, T.kupec, { email: "tujec@example.com", allow_guest: "da" });
    assert(r.status === 404, "B: allow_guest, ki ni boolean true -> kot stari odjemalec (404)", r.status);
    // admin na A (stikalo prazno) sme
    const adminVst = await kupi(T.admin, E0, 1);
    r = await api("POST", `/tickets/${adminVst[0].id}/transfer`, T.admin, { email: "admin-prijatelj@example.com", allow_guest: true });
    assert(r.status === 200 && r.body.result === "ok", "A: admin sme pri izklopljenem stikalu (ekipa testira v produkciji)", r.body);
    assert(await cakaj(() => poslanoNa("admin-prijatelj@example.com").length === 1), "A: mail adminovemu prijatelju poslan");

    // ============================================================
    console.log("\n# 2. Starost");
    const v18 = await kupi(T.kupec2, E18, 6);
    r = await apiB("POST", `/tickets/${v18[0].id}/transfer`, T.kupec2, { email: "gost18@example.com", allow_guest: true });
    assert(r.status === 400 && r.body.error === "age_confirmation_required" && r.body.min_age === 18 && r.body.message, "gost, dogodek 18+, brez age_confirmed: 400 age_confirmation_required (min_age 18)", r.body);
    r = await apiB("POST", `/tickets/${v18[0].id}/transfer`, T.kupec2, { email: "gost18@example.com", allow_guest: true, age_confirmed: false });
    assert(r.status === 400 && r.body.error === "age_confirmation_required", "age_confirmed: false = brez potrditve -> 400", r.body);
    v = await vstopnica(v18[0].id);
    assert(v.holder_is_guest === false && v.serial === v18[0].serial, "400: vstopnica nespremenjena");
    r = await apiB("POST", `/tickets/${v18[0].id}/transfer`, T.kupec2, { email: "gost18@example.com", allow_guest: true, age_confirmed: true });
    assert(r.status === 200, "gost 18+ s potrditvijo -> 200", r.body);
    let tr = (await pool.query("SELECT to_guest, to_user_id, to_email, age_confirmed_min FROM ticket_transfers WHERE ticket_id=$1", [v18[0].id])).rows[0];
    assert(tr.to_guest === true && tr.to_user_id === null && tr.to_email === "gost18@example.com" && tr.age_confirmed_min === 18, "zapis prenosa: to_guest, brez uporabnika, potrjena meja 18", tr);
    // dogodek 0+ brez potrditve: ni potrebna
    r = await apiB("POST", `/tickets/${t1.id}/transfer`, T.kupec, { email: "gost0@example.com", allow_guest: true });
    assert(r.status === 200, "gost, dogodek 0+, brez age_confirmed -> 200 (meja 0)", r.body);
    tr = (await pool.query("SELECT age_confirmed_min FROM ticket_transfers WHERE ticket_id=$1", [t1.id])).rows[0];
    assert(tr.age_confirmed_min === null, "meja 0: potrditev ni shranjena");
    // VIP s paketom: meja = max(min_age, 18), potrditev VEDNO obvezna
    const PLAN = { width: 24, height: 16, elements: [{ type: "stage", x: 8, y: 0, w: 8, h: 3, label: "" }] };
    const mize = Array.from({ length: 4 }, (_, i) => ({ label: `T${i + 1}`, x: 1 + i * 4, y: 5, w: 2, h: 2, shape: "round", seats: 4, price_cents: 20000 }));
    r = await apiB("PUT", "/business/vip", T.lastnik, { plan: PLAN, tables: mize, packages: [{ name: "Jameson 0,7 l", description: "4x Red Bull" }] });
    assert(r.status === 200, "VIP: miza + paket", r.body);
    const M = r.body.tables.map(x => x.id), P = r.body.packages[0].id;
    let rr = await apiB("POST", `/events/${EV}/tables/${M[0]}/orders`, T.kupec3, { package_id: P });
    assert(rr.status === 201 && rr.body.tickets.length === 4, "kupec3 kupi mizo s paketom (4 vstopnice)", rr.body);
    const vip = rr.body.tickets;
    r = await apiB("POST", `/tickets/${vip[0].id}/transfer`, T.kupec3, { email: "vipgost@example.com", allow_guest: true });
    assert(r.status === 400 && r.body.error === "age_confirmation_required" && r.body.min_age === 18, "VIP paket, dogodek 0+, gost brez potrditve: 400 z min_age 18", r.body);
    r = await apiB("POST", `/tickets/${vip[0].id}/transfer`, T.kupec3, { email: "vipgost@example.com", allow_guest: true, age_confirmed: true });
    assert(r.status === 200 && r.body.result === "ok", "VIP paket, gost, s potrditvijo -> 200 (Martin: kupec mize razdeli vstopnice)", r.body);
    tr = (await pool.query("SELECT age_confirmed_min FROM ticket_transfers WHERE ticket_id=$1", [vip[0].id])).rows[0];
    assert(tr.age_confirmed_min === 18, "VIP: shranjena potrjena meja 18");
    rr = await apiB("POST", `/events/${E21}/tables/${M[1]}/orders`, T.kupec3, { package_id: P });
    assert(rr.status === 201, "kupec3 kupi mizo s paketom na dogodku 21+", rr.body);
    r = await apiB("POST", `/tickets/${rr.body.tickets[0].id}/transfer`, T.kupec3, { email: "vip21@example.com", allow_guest: true });
    assert(r.status === 400 && r.body.min_age === 21, "VIP na dogodku 21+: min_age v napaki = 21 (strozja meja dogodka)", r.body);
    // Prenos na RACUN (SPREMEMBA 2): potrditev posiljatelja
    r = await apiB("POST", `/tickets/${v18[1].id}/transfer`, T.kupec2, { email: "brezdatuma@outly.si" });
    assert(r.status === 403 && /date of birth/.test(r.body), "racun brez datuma rojstva, dogodek 18+, BREZ potrditve (stari odjemalec): 403 kot doslej", r.body);
    r = await apiB("POST", `/tickets/${v18[1].id}/transfer`, T.kupec2, { email: "mladi@outly.si", age_confirmed: true });
    assert(r.status === 403 && /at least 18/.test(r.body), "racun z VPISANIM datumom pod mejo (17) + potrditev: 403 (znan mladoletnik)", r.body);
    r = await apiB("POST", `/tickets/${v18[1].id}/transfer`, T.kupec2, { email: "brezdatuma@outly.si", age_confirmed: true });
    assert(r.status === 200 && r.body.message === "Ticket sent to brezdatuma." && r.body.ticket.holder_username === "brezdatuma", "racun brez datuma + age_confirmed: 200 (prej 403); sporocilo kot doslej (uporabnisko ime)", r.body);
    tr = (await pool.query("SELECT age_confirmed_min, to_guest FROM ticket_transfers WHERE ticket_id=$1", [v18[1].id])).rows[0];
    assert(tr.age_confirmed_min === 18 && tr.to_guest === false, "prenos na racun: potrditev shranjena, to_guest false", tr);
    r = await apiB("POST", `/tickets/${v18[2].id}/transfer`, T.kupec2, { email: "brezdatuma@outly.si", allow_guest: true });
    assert(r.status === 400 && r.body.error === "age_confirmation_required" && r.body.min_age === 18, "allow_guest brez age_confirmed, prejemnik Z racunom brez datuma na 18+: ISTA 400 kot za gosta (brez razkritja racuna)", r.body);
    r = await apiB("POST", `/tickets/${v18[2].id}/transfer`, T.kupec2, { email: "racun@outly.si" });
    assert(r.status === 200, "racun z datumom 25 let, brez potrditve (stari odjemalec) -> 200 kot doslej", r.body);
    // paket + prenos na racun brez datuma
    r = await apiB("POST", `/tickets/${vip[1].id}/transfer`, T.kupec3, { email: "brezdatuma@outly.si" });
    assert(r.status === 403 && /bottle package/.test(r.body), "paket, racun brez datuma, brez potrditve -> 403 (kot doslej)", r.body);
    r = await apiB("POST", `/tickets/${vip[1].id}/transfer`, T.kupec3, { email: "brezdatuma@outly.si", age_confirmed: true });
    assert(r.status === 200, "paket, racun brez datuma, age_confirmed -> 200", r.body);
    r = await apiB("POST", `/tickets/${vip[2].id}/transfer`, T.kupec3, { email: "mladi@outly.si", age_confirmed: true });
    assert(r.status === 403 && /bottle package/.test(r.body), "paket, znan 17-letnik + potrditev -> 403", r.body);
    // stikalo ne velja za prenos na racun s potrditvijo (A, navaden uporabnik)
    const aV = await kupi(T.kupec2, E18, 1);
    r = await api("POST", `/tickets/${aV[0].id}/transfer`, T.kupec2, { email: "brezdatuma@outly.si", age_confirmed: true });
    assert(r.status === 200, "A (stikalo izklopljeno): potrditev starosti pri prenosu na RACUN deluje (ni vezana na stikalo)", r.body);

    // ============================================================
    console.log("\n# 3. E-naslov z racunom: enoten odgovor, brez maila");
    const prejR = R.poslano.length;
    r = await apiB("POST", `/tickets/${t2.id}/transfer`, T.kupec, { email: " Racun@Outly.SI ", allow_guest: true, age_confirmed: false });
    assert(r.status === 200 && r.body.result === "ok" && r.body.message === "Ticket sent to racun@outly.si." && r.body.ticket.holder_username === null && r.body.ticket.holder_email === "racun@outly.si" && r.body.ticket.transferred === true, "racun: enoten odgovor (sporocilo z e-naslovom, holder_username null)", r.body);
    v = await vstopnica(t2.id);
    const racunId = (await pool.query("SELECT id FROM users WHERE email='racun@outly.si'")).rows[0].id;
    assert(v.holder_user_id === racunId && v.holder_is_guest === false && v.serial !== t2.serial, "vstopnica je na racunu, serial zamenjan");
    // mail sledi prenosu takoj (brez ponovitev): pogoj »noben mail« preverimo, ko je prispel mail PREZGODEJ naslednjega prenosa gostu (urejenost dogodkov, ne cas)
    r = await apiB("GET", "/me/tickets", T.racun);
    assert(r.body.some(t => t.id === t2.id && t.transferred === true), "racun vidi vstopnico v /me/tickets");
    // gost, odgovor enake oblike
    r = await apiB("POST", `/tickets/${t3.id}/transfer`, T.kupec, { email: "ni-racuna@example.com", allow_guest: true });
    assert(await cakaj(() => poslanoNa("ni-racuna@example.com").length === 1), "(urejenost) mail gostu poslan");
    assert(R.poslano.length === prejR + 1 && poslanoNa("racun@outly.si").length === 0, "prenos na racun: noben mail (od prenosa na racun do maila gostu je poslan natanko 1)", R.poslano.length - prejR);
    assert(r.status === 200 && Object.keys(r.body).sort().join() === "message,result,ticket" && r.body.message === "Ticket sent to ni-racuna@example.com." && r.body.ticket.holder_username === null && r.body.ticket.holder_email === "ni-racuna@example.com", "gost: odgovor enake oblike kot za racun", r.body);
    // nepotrjen racun = gost
    await pool.query("UPDATE users SET email_verified=FALSE WHERE email='nepotrjen@outly.si'");
    r = await apiB("POST", `/tickets/${t4.id}/transfer`, T.kupec, { email: "nepotrjen@outly.si", allow_guest: true });
    assert(r.status === 200, "racun z nepotrjenim e-naslovom + allow_guest: gost (200)", r.body);
    v = await vstopnica(t4.id);
    assert(v.holder_is_guest === true && v.holder_guest_email === "nepotrjen@outly.si", "vstopnica gostujoca (e-naslov nepotrjenega racuna)", v);
    r = await apiB("POST", `/tickets/${t5.id}/transfer`, T.kupec, { email: "kupec@outly.si", allow_guest: true });
    assert(r.status === 400 && /already hold/.test(r.body), "prenos samemu sebi: 400", r.body);
    r = await apiB("POST", `/tickets/${t5.id}/transfer`, T.kupec, { email: "a@b.c", allow_guest: true });
    assert(r.status === 400 && r.body.error === "invalid_email", "neveljaven naslov (gost): 400 invalid_email", r.body);
    r = await apiB("POST", `/tickets/${t5.id}/transfer`, T.kupec, { email: "ni-naslova", allow_guest: true });
    assert(r.status === 400, "naslov brez @: 400", r.body);
    assert((await vstopnica(t5.id)).holder_is_guest === false, "zavrnjeni prenosi ne spremenijo vstopnice");

    // ============================================================
    console.log("\n# 4. Gost: serial, hash zetona, mail");
    const stUserjev = (await pool.query("SELECT COUNT(*)::int AS n FROM users")).rows[0].n;
    // sken starega QR po prenosu: kupec ima QR t6, ki ga po prenosu ne sme veljati
    const staraKoda = t6.qr, staraSerial = t6.serial;
    r = await apiB("POST", `/tickets/${t6.id}/transfer`, T.kupec, { email: "  Prijatelj@Example.COM ", allow_guest: true });
    assert(r.status === 200 && r.body.message === "Ticket sent to prijatelj@example.com.", "prenos gostu 200", r.body);
    assert(!/guest\/ticket|#t=|token/i.test(r.tekst), "odgovor ne vsebuje povezave ali zetona (posiljatelj zetona ne dobi)", r.tekst);
    v = await vstopnica(t6.id);
    assert(v.holder_is_guest === true && v.holder_guest_email === "prijatelj@example.com" && v.holder_user_id === null && v.serial !== staraSerial, "v bazi: gostujoci imetnik, e-naslov normaliziran, serial NOV", v);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM users")).rows[0].n === stUserjev, "gost NI vrstica v users");
    r = await apiB("POST", "/business/tickets/scan", T.lastnik, { qr: staraKoda });
    assert([404, 409].includes(r.status) && r.body.result !== "ok", "stara koda posiljatelja ne velja (sken)", r.body);
    r = await apiB("POST", "/business/tickets/scan", T.lastnik, { serial: staraSerial });
    assert([404, 409].includes(r.status) && r.body.result !== "ok", "stari serial ne velja (rocni vnos)", r.body);
    assert(await cakaj(() => poslanoNa("prijatelj@example.com").length >= 1), "mail na naslov gosta poslan");
    assert(await cakaj(async () => (await poslanoOb(t6.id)) !== null), "v bazi je zapisano »poslano« (pospravljalec po tem ne more poslati drugega: pogoj sent_at IS NULL)");
    const mails = poslanoNa("prijatelj@example.com");
    assert(mails.length === 1, "mail natanko enkrat (tudi po pospravljalcu)", mails.length);
    const m0 = mails[0];
    const z6 = zetonIzMaila(m0);
    assert(z6 && /^[A-Za-z0-9_-]{43}$/.test(z6), "mail: povezava /app/guest/ticket#t=<zeton> (fragment)", (m0.html || "").slice(0, 80));
    assert(/^https:\/\/outly\.test\/app\/guest\/ticket#t=/.test((/https:\/\/[^\s"<]+guest\/ticket#t=[A-Za-z0-9_-]+/.exec(m0.text || "") || [""])[0]) && !(m0.text || "").includes("?t="), "mail: povezava v besedilu z osnovo APP_URL, zeton v fragmentu");
    assert(m0.reply_to === "luka@outly.si" && /^Outly <test@outly\.test>$/.test(m0.from), "mail: reply-to luka@outly.si, posiljatelj EMAIL_FROM", [m0.reply_to, m0.from]);
    assert(/^kupec sent you a ticket for Prenos Noc$/.test(m0.subject), "zadeva: uporabnisko ime posiljatelja + dogodek", m0.subject);
    const vse = (m0.html || "") + (m0.text || "");
    assert(!vse.includes("kupec@outly.si") && !vse.includes("prijatelj@example.com"), "mail: brez e-naslova posiljatelja in prejemnika v vsebini");
    assert(!/<script|pixel|track/i.test(m0.html || "") && !/<img[^>]+src="(?!cid:)/i.test(m0.html || ""), "mail: brez sledilnikov in zunanjih slik");
    const pr = m0.attachments || [];
    const png = pr.find(x => x.content_type === "image/png");
    assert(png && png.content_id === "ticket-qr-1" && /src="cid:ticket-qr-1"/.test(m0.html) && Buffer.from(png.content, "base64").subarray(0, 8).equals(PNG_PODPIS), "mail: koda QR kot vgrajena slika (PNG, content_id, cid: v HTML)", pr.map(x => [x.filename, x.content_type, x.content_id]));
    const pdfP = pr.find(x => x.content_type === "application/pdf");
    const pdfB = pdfP ? Buffer.from(pdfP.content, "base64").toString("latin1") : "";
    assert(pdfP && pdfP.filename === "outly-ticket.pdf" && pdfB.startsWith("%PDF-") && pdfB.includes("%%EOF"), "mail: priloga PDF", pdfP && pdfP.filename);
    assert(pdfB.includes("Prenos Noc") && pdfB.includes("Pure Club") && !pdfB.includes("prijatelj") && !pdfB.includes("kupec"), "PDF: dogodek in klub, brez e-naslova prejemnika in posiljatelja");
    // xref
    const xs = /startxref\n(\d+)\n%%EOF/.exec(pdfB);
    assert(xs && pdfB.slice(Number(xs[1]), Number(xs[1]) + 4) === "xref", "PDF: startxref kaze na tabelo xref");
    const bes = m0.text || "";
    const ob = (re, opis) => assert(re.test(bes), `mail (besedilo): ${opis}`, bes.slice(0, 120));
    ob(/NEXT DIMENSIONS, družba za marketing, d\.o\.o\., Trebče 81, 3256 Bistrica ob Sotli, luka@outly\.si/, "obvestilo GDPR 14: upravljavec");
    ob(/legitimate interest \(GDPR Article 6\(1\)\(f\)\): kupec wanted to pass this ticket on to you/, "namen in pravna podlaga (6(1)(f)) z uporabniskim imenom posiljatelja");
    ob(/Where we got it: kupec, an Outly user, entered your email address/, "vir podatka");
    ob(/Data: your email address, the ticket and event, the sender's confirmation that you meet the age limit/, "vrste podatkov");
    ob(/Recipients: Resend \(email delivery\)\. The organiser \(Pure Club\) only sees that the ticket was passed on to a guest, not your email address/, "prejemniki; organizator naslova ne vidi");
    ob(/Transfer outside the EEA/, "prenos izven EGP");
    ob(/Retention: we delete your email address 30 days after the event ends/, "rok hrambe");
    ob(/Your rights: access, rectification, erasure, restriction.*Information Commissioner/, "pravice + pritozba");
    ob(/RIGHT TO OBJECT\nDon't want us to process your email address\? You have the right to object at any time: reply to this email/, "pravica do ugovora (21(4)) v LOCENEM odstavku");
    ob(/THIS IS YOUR TICKET\nThis email and the attached PDF are your ticket\. The QR code is valid for one entry: whoever shows it first gets in\. Don't forward this email, post the code or share the link\./, "varnostno besedilo");
    ob(/If you create an Outly account with this email, the ticket will appear there\./, "en nevtralen stavek o prevzemu v racun");
    ob(/Age limit|No age limit\./, "starostna meja");
    ob(/Pure Club, Trs?g 1|Pure Club, Trg 1, Ljubljana/, "kraj");
    ob(/\(Ljubljana time\)/, "datum in ura");
    ob(/Organiser: Pure Club \(info@pure\.test\)/, "organizator + kontakt");
    ob(/One entry per code\.[\s\S]*house rules or the law[\s\S]*Reselling[\s\S]*refund goes to the person who bought the ticket/, "pravila vstopnice");
    ob(/NOT FOR YOU\?\nIf you were not expecting this ticket, reply to this email/, "»Ni zate?«");
    assert(!/download|app store|discount|promo|newsletter|unsubscribe/i.test(bes), "mail: brez promocije");
    const mailV18 = poslanoNa("gost18@example.com")[0];
    assert(await cakaj(() => poslanoNa("gost18@example.com").length >= 1) && /Age limit: 18\+.*photo ID/.test(poslanoNa("gost18@example.com")[0].text), "mail za dogodek 18+: starostna meja + osebni dokument", mailV18 && mailV18.text.slice(0, 100));
    assert(await cakaj(() => poslanoNa("vipgost@example.com").length >= 1), "mail za VIP vstopnico poslan");
    assert(/VIP table T1, package: Jameson 0,7 l/.test(poslanoNa("vipgost@example.com")[0].text) && /Age limit: 18\+ \(table with a drinks package\)/.test(poslanoNa("vipgost@example.com")[0].text), "VIP mail: miza, paket, meja 18+ (paket)");
    // v bazi hash zetona
    const h6 = hash(z6);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni_vstopnic WHERE token_hash=$1 AND ticket_id=$2", [h6, t6.id])).rows[0].n === 1, "v bazi: sha256 zetona (hex), vezan na vstopnico");
    const povsod = (await pool.query("SELECT (SELECT string_agg(t::text, ' ') FROM tickets t) || (SELECT string_agg(z::text, ' ') FROM gost_zetoni_vstopnic z) || (SELECT string_agg(x::text, ' ') FROM ticket_transfers x) AS t")).rows[0].t;
    assert(!povsod.includes(z6), "cistopisa zetona nikjer v tickets / gost_zetoni_vstopnic / ticket_transfers");

    // ============================================================
    console.log("\n# 5. GET /guest/ticket");
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": z6 });
    assert(r.status === 200 && r.headers.get("cache-control") === "no-store", "200 + Cache-Control: no-store", r.status);
    const gt = r.body.ticket, ge = r.body.event;
    assert(gt && gt.id === t6.id && gt.serial === v.serial && gt.qr && gt.status === "valid" && gt.transferable === false && gt.event_title === "Prenos Noc" && gt.transferred === true, "ticket: oblika kot /me/tickets (id, serial, qr, status, event), transferable false", gt);
    assert(ge && ge.id === E0 && ge.title === "Prenos Noc" && ge.club_name === "Pure Club" && ge.min_age === 0 && "start_at" in ge && "end_at" in ge && "poster_url" in ge && ge.address === "Trg 1" && ge.city === "Ljubljana", "event: id, title, start_at, end_at, poster_url, min_age, club_name, address, city", ge);
    assert(!JSON.stringify(r.body).includes("prijatelj@example.com") && !JSON.stringify(r.body).includes("kupec@outly.si"), "odgovor brez e-naslovov (gosta in kupca)");
    assert(gt.holder_email === null || gt.holder_email === undefined, "holder_email ni na voljo");
    r = await apiB("GET", "/guest/ticket", null, undefined, {});
    const brez = r;
    assert(r.status === 404, "brez zetona: 404", r.status);
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": crypto.randomBytes(32).toString("base64url") });
    assert(r.status === 404 && r.tekst === brez.tekst, "napacen zeton: enak 404 kot brez", r.tekst);
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": "kratek" });
    assert(r.status === 404 && r.tekst === brez.tekst, "neveljavna oblika: enak 404");
    const zOrder = await apiB("GET", "/guest/order", null, undefined, { "x-guest-token": z6 });
    assert(zOrder.status === 404, "zeton vstopnice ne odpre /guest/order", zOrder.status);
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": z6 + "x" });
    assert(r.status === 404, "zeton z dodanim znakom: 404");
    // meja neuspesnih na B = 3: nad mejo 429 za neveljavne, veljaven zeton NIKOLI
    const isti = { "x-forwarded-for": "10.77.0.1" };   // meja neuspesnih je po IP
    for (let i = 0; i < 3; i++) await apiB("GET", "/guest/ticket", null, undefined, { ...isti, "x-guest-token": crypto.randomBytes(32).toString("base64url") });
    r = await apiB("GET", "/guest/ticket", null, undefined, { ...isti, "x-guest-token": crypto.randomBytes(32).toString("base64url") });
    assert(r.status === 429 && r.headers.get("retry-after"), "neveljaven zeton nad mejo neuspesnih: 429 + Retry-After", r.status);
    r = await apiB("GET", "/guest/ticket", null, undefined, { ...isti, "x-guest-token": z6 });
    assert(r.status === 200, "VELJAVEN zeton nad mejo neuspesnih: 200 (nikoli 429)", r.status);
    // sken gostove kode: en vstop
    const koda = r.body.ticket.qr;
    r = await apiB("POST", "/business/tickets/scan", T.vratar, { qr: koda });
    assert(r.status === 200 && r.body.result === "ok" && r.body.ticket.holder_username === "Guest" && r.body.ticket.is_guest_holder === true, "vratar skenira gostovo kodo: ok, imetnik »Guest«", r.body);
    assert(!JSON.stringify(r.body).includes("prijatelj@example.com"), "odgovor skena: brez e-naslova gosta");
    r = await apiB("POST", "/business/tickets/scan", T.vratar, { qr: koda });
    assert(r.status === 409 && r.body.result === "already_used", "drugi sken iste kode: 409 already_used", r.body);
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": z6 });
    assert(r.status === 200 && r.body.ticket.status === "used", "pogled gosta po vstopu: status used", r.body.ticket && r.body.ticket.status);

    // ============================================================
    console.log("\n# 6. Pogledi");
    r = await apiB("GET", "/me/orders", T.kupec);
    const ord = r.body.find(o => o.tickets.some(t => t.id === t6.id));
    const kt = ord && ord.tickets.find(t => t.id === t6.id);
    assert(kt && kt.transferred === true && kt.serial === null && kt.qr === null && kt.holder_username === "Guest" && !("holder_email" in kt) && kt.holder_id === null, "kupec (/me/orders): vstopnica prenesena, brez QR/serial/e-naslova, imetnik Guest", kt);
    assert(!JSON.stringify(r.body).includes("prijatelj@example.com"), "/me/orders kupca: e-naslova gosta ni (tudi ce ga je vpisal sam)");
    r = await apiB("GET", "/me/tickets", T.kupec);
    assert(Array.isArray(r.body) && !r.body.some(t => t.id === t6.id), "kupec (/me/tickets): vstopnica, poslana gostu, ni vec na seznamu");
    for (const [kdo, tok] of [["lastnik", T.lastnik], ["vratar", T.vratar]]) {
      r = await apiB("GET", `/business/events/${E0}/tickets`, tok);
      const x = r.body.find(t => t.id === t6.id);
      assert(r.status === 200 && x && x.holder_username === "Guest" && x.is_guest_holder === true && !x.holder_email && x.holder_id === null, `${kdo}: poslovni pogled: imetnik Guest, is_guest_holder, brez e-naslova`, x);
      assert(!r.tekst.includes("prijatelj@example.com") && !r.tekst.includes("ni-racuna@example.com") && !r.tekst.includes("nepotrjen@outly.si"), `${kdo}: nikjer e-naslova gostujocega imetnika`);
    }
    r = await apiB("GET", `/business/events/${E0}/scan-list`, T.vratar);
    assert(r.status === 200 && r.body.tickets.find(t => t.serial === v.serial).holder_username === "Guest" && r.body.transferred_serials.includes(staraSerial), "scan-list: imetnik Guest; stari serial med preneseni", r.status);
    assert(!r.tekst.includes("example.com"), "scan-list brez e-naslovov");
    r = await apiB("GET", "/me/friends/plans", T.kupec).catch(() => ({ status: 0 }));
    assert([200, 404].includes(r.status), "nacrti prijateljev: gostujoci imetnik ne podre poizvedb", r.status);

    // ============================================================
    console.log("\n# 7. Prevzem v racun");
    const t7pre = await vstopnica(t7.id);
    r = await apiB("POST", `/tickets/${t7.id}/transfer`, T.kupec, { email: "novi@outly.si", allow_guest: true });   // racun obstaja (verified) -> prenos na racun
    assert(r.status === 200, "(izhodisce) novi@ ima racun -> prenos na racun", r.body);
    // pravi prevzem: naslov, ki racuna se nima; racun nastane po prenosu
    r = await apiB("POST", `/tickets/${t8.id}/transfer`, T.kupec, { email: "kasneje@example.com", allow_guest: true });
    assert(r.status === 200, "prenos gostu (racun bo nastal pozneje)", r.body);
    assert(await cakaj(() => poslanoNa("kasneje@example.com").length === 1), "mail poslan");
    const zK = zetonIzMaila(poslanoNa("kasneje@example.com")[0]);
    const vK = await vstopnica(t8.id);
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": zK });
    assert(r.status === 200, "pred prevzemom zeton velja");
    const TK = zeton("kasneje@example.com", uuid(100));
    r = await apiB("GET", "/me", TK);
    assert(r.status === 200, "gost se registrira (GET /me s potrjenim e-naslovom)", r.status);
    const kUser = (await pool.query("SELECT id FROM users WHERE email='kasneje@example.com'")).rows[0].id;
    const vK2 = await vstopnica(t8.id);
    assert(vK2.holder_user_id === kUser && vK2.holder_is_guest === false && vK2.holder_guest_email === null, "vstopnica je njegova (holder_user_id), e-naslov gosta izbrisan", vK2);
    assert(vK2.serial === vK.serial, "serial se NE zamenja (PDF/koda v mailu velja naprej)");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni_vstopnic WHERE ticket_id=$1", [t8.id])).rows[0].n === 0, "zetoni preklicani (v bazi jih ni vec)");
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": zK });
    assert(r.status === 404, "po prevzemu zeton: 404 (enak kot neveljaven)");
    r = await apiB("GET", "/me/tickets", TK);
    const pt = Array.isArray(r.body) && r.body.find(t => t.id === t8.id);
    assert(pt && pt.transferred === true && pt.buyer_username === "kupec" && pt.serial === vK.serial && pt.holder_username === "kasneje" && pt.qr, "/me/tickets prevzemnika: transferred, buyer_username = kupec, QR", pt);
    r = await apiB("GET", "/me/tickets/received", TK);
    assert(r.status === 200 && r.body.received.some(x => x.ticket_id === t8.id && x.from && x.from.username === "kupec"), "obvestilo »kupec ti je poslal vstopnico« (received)", r.body);
    assert(!JSON.stringify((await apiB("GET", "/me/orders", T.kupec)).body).includes("kasneje@example.com"), "kupec: e-naslova prevzemnika ne vidi");
    // nepotrjen racun: t4 (nepotrjen@outly.si) se ne prevzame, dokler ni potrjen
    r = await apiB("GET", "/me", T.nepotrjen);
    assert((await vstopnica(t4.id)).holder_is_guest === true, "nepotrjen racun: vstopnica se NE prevzame");
    await pool.query("UPDATE users SET email_verified=TRUE WHERE email='nepotrjen@outly.si'");
    r = await apiB("GET", "/me", T.nepotrjen);
    v = await vstopnica(t4.id);
    assert(v.holder_is_guest === false && v.holder_user_id !== null, "po potrditvi e-naslova se vstopnica prevzame", v);
    // tuj uporabnik z drugim e-naslovom ne dobi
    assert((await vstopnica(t3.id)).holder_is_guest === true, "vstopnica drugemu e-naslovu ostane gostujoca");

    // ============================================================
    console.log("\n# 8. Napaka Resenda, pospravljalec, hramba");
    const eT = await dogodek("Prenos Hramba", 0);
    const hV = await kupi(T.kupec, eT, 3);
    R.napaka = true;
    r = await apiB("POST", `/tickets/${hV[0].id}/transfer`, T.kupec, { email: "napaka@example.com", allow_guest: true });
    assert(r.status === 200, "napaka Resenda ne podre prenosa (200)", r.body);
    assert(await cakaj(async () => (await pool.query("SELECT holder_guest_mail_attempts AS n FROM tickets WHERE id=$1", [hV[0].id])).rows[0].n >= 1), "poskus je zabelezen");
    assert(poslanoNa("napaka@example.com").length === 0 && (await poslanoOb(hV[0].id)) === null, "mail se ni poslan (Resend zavraca), »poslano« ni zapisano");
    assert(!/napaka@example\.com/.test(a.log + b.log + c.log), "dnevnik brez e-naslova");
    R.napaka = false;
    assert(await cakaj(() => poslanoNa("napaka@example.com").length === 1, 8000), "pospravljalec poslje mail, ko Resend spet dela");
    assert(await cakaj(async () => (await poslanoOb(hV[0].id)) !== null), "»poslano« zapisano");
    assert(poslanoNa("napaka@example.com").length === 1, "pospravljalec ne poslje drugega (najvec enkrat ob uspehu)");
    const hZ = zetonIzMaila(poslanoNa("napaka@example.com")[0]);
    // anonimizacija: konec dogodka + 30 dni
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '40 days', end_at = NOW() - INTERVAL '39 days' WHERE id=$1", [eT]);
    assert(await cakaj(async () => (await pool.query("SELECT holder_guest_email FROM tickets WHERE id=$1", [hV[0].id])).rows[0].holder_guest_email === null, 8000), "po koncu dogodka + 30 dni: e-naslov imetnika izbrisan");
    v = await vstopnica(hV[0].id);
    assert(v.holder_is_guest === true && v.holder_user_id === null, "vstopnica OSTANE gostujoca (ne postane spet kupceva)", v);
    assert((await pool.query("SELECT to_email FROM ticket_transfers WHERE ticket_id=$1", [hV[0].id])).rows[0].to_email.startsWith("izbrisan-"), "zapis prenosa: e-naslov nadomescen z neosebno oznako");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni_vstopnic WHERE ticket_id=$1", [hV[0].id])).rows[0].n === 0, "zetoni izbrisani");
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": hZ });
    assert(r.status === 404, "po poteku zeton: 404");
    r = await apiB("GET", `/business/events/${eT}/tickets`, T.lastnik);
    const hx = r.body.find(t => t.id === hV[0].id);
    assert(hx && hx.holder_username === "Guest" && hx.holder_id === null, "poslovni pogled po anonimizaciji: se vedno Guest", hx);
    // poteklega zetona ni mogoce »oziviti« s casom: zeton starega dogodka
    const r2 = await apiB("GET", "/me/tickets", T.kupec);
    assert(!r2.body.some(t => t.id === hV[0].id), "kupec ga ne dobi nazaj po anonimizaciji");

    // ============================================================
    console.log("\n# 9. Zloraba");
    // C: meja 3 na posiljatelja na 24 h, 2 na naslov
    const cV = await (async () => { const rr2 = await apiC("POST", `/events/${E0}/orders`, T.kupec4, { quantity: 6 }); return rr2.body.tickets; })();
    r = await apiC("POST", `/tickets/${cV[0].id}/transfer`, T.kupec4, { email: "enak@example.com", allow_guest: true });
    assert(r.status === 200, "C: 1. prenos na naslov", r.body);
    r = await apiC("POST", `/tickets/${cV[1].id}/transfer`, T.kupec4, { email: "enak@example.com", allow_guest: true });
    assert(r.status === 200, "C: 2. prenos na isti naslov", r.body);
    r = await apiC("POST", `/tickets/${cV[2].id}/transfer`, T.kupec4, { email: "enak@example.com", allow_guest: true });
    assert(r.status === 429 && r.body.error === "guest_transfer_limit" && r.headers.get("retry-after"), "C: 3. prenos na isti naslov (meja 2/24 h): 429 guest_transfer_limit", r);
    v = await vstopnica(cV[2].id);
    assert(v.holder_is_guest === false && v.serial === cV[2].serial, "429: vstopnica nespremenjena");
    r = await apiC("POST", `/tickets/${cV[2].id}/transfer`, T.kupec4, { email: "drug@example.com", allow_guest: true });
    assert(r.status === 200, "C: 3. prenos posiljatelja na drug naslov (meja 3/24 h)", r.body);
    r = await apiC("POST", `/tickets/${cV[3].id}/transfer`, T.kupec4, { email: "tretji@example.com", allow_guest: true });
    assert(r.status === 429 && r.body.error === "guest_transfer_limit", "C: 4. prenos posiljatelja (meja 3/24 h): 429", r.body);
    r = await apiC("POST", `/tickets/${cV[3].id}/transfer`, T.kupec4, { email: "racun@outly.si", allow_guest: true });
    assert(r.status === 429 && r.body.error === "guest_transfer_limit", "C: tudi prenos na RACUN (allow_guest) steje v mejo posiljatelja: 429 enako kot za gosta (brez razkritja racuna)", r.body);
    // hkratnost: dva prenosa iste vstopnice (B) -> en uspe
    const hk = await kupi(T.kupec, E0, 1);
    const prejHk = R.poslano.length;
    const [x1, x2] = await Promise.all([
      apiB("POST", `/tickets/${hk[0].id}/transfer`, T.kupec, { email: "hk1@example.com", allow_guest: true }),
      apiB("POST", `/tickets/${hk[0].id}/transfer`, T.kupec, { email: "hk2@example.com", allow_guest: true })]);
    assert([x1.status, x2.status].sort().join() === "200,404", "hkratna prenosa iste vstopnice: en 200, drugi 404 (ni vec imetnik)", [x1.status, x2.status]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM ticket_transfers WHERE ticket_id=$1", [hk[0].id])).rows[0].n === 1, "natanko en zapis prenosa");
    assert(await cakaj(async () => (await poslanoOb(hk[0].id)) !== null), "»poslano« zapisano");
    assert(R.poslano.length === prejHk + 1, "natanko en mail", R.poslano.length - prejHk);
    // gost ne more naprej: vstopnica gosta ni na /me/tickets nikogar, prenos s kupcevim zetonom -> 404
    r = await apiB("POST", `/tickets/${hk[0].id}/transfer`, T.kupec, { email: "hk3@example.com", allow_guest: true });
    assert(r.status === 404, "kupec ne more znova prenesti vstopnice, ki jo drzi gost (404)", r.status);
    // user_id + allow_guest: gost samo pri e-naslovu (prejemnik po id mora biti prijatelj)
    r = await apiB("POST", `/tickets/${t5.id}/transfer`, T.kupec, { user_id: 99999, allow_guest: true });
    assert(r.status === 404 && /friends/.test(r.body), "user_id (ni prijatelj) + allow_guest: 404 kot prej", r.body);

    // ============================================================
    console.log("\n# 10. QA 1. krog (PR #161): sockasnost meje na naslov, normalizacija, dnevna meja, starost, brisanje, zanka dogodkov");
    const D = `http://127.0.0.1:${PORT_D}`, E = `http://127.0.0.1:${PORT_E}`;
    const d = zagon(PORT_D, { PRENOS_BREZ_RACUNA: "vsi", GOST_PRENOS_NA_DAN: "1000", GOST_PRENOS_NA_NASLOV: "2" }); dodatni.push(d);
    await cakajStreznik(D);
    const apiD = (m, p, t, b2, g) => zahtevek(D, m, p, t, b2, g);
    // 6 posiljateljev, vsak ima vstopnico
    const posilj = [];
    for (let i = 1; i <= 6; i++) {
      const em = `posilj${i}@outly.si`; const tok = zeton(em, uuid(200 + i));
      await apiB("GET", "/me", tok);
      posilj.push({ tok, vst: (await kupi(tok, E0, 2)) });
    }
    // S2: sockasnost: 6 posiljateljev hkrati na ISTI naslov, meja 2 -> natanko 2 uspeta (zaklep na naslov)
    let rez = await Promise.all(posilj.map(x => apiD("POST", `/tickets/${x.vst[0].id}/transfer`, x.tok, { email: "skupni@example.com", allow_guest: true })));
    const st200 = rez.filter(x => x.status === 200).length, st429 = rez.filter(x => x.status === 429 && x.body.error === "guest_transfer_limit").length;
    assert(st200 === 2 && st429 === 4, "6 hkratnih posiljateljev na isti naslov (meja 2): natanko 2 x 200 in 4 x 429", rez.map(x => x.status));
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM ticket_transfers WHERE to_email = 'skupni@example.com'")).rows[0].n === 2, "v bazi natanko 2 prenosa na naslov");
    // normalizacija: +oznaka in pike (gmail) so ISTI nabiralnik
    r = await apiD("POST", `/tickets/${posilj[2].vst[1].id}/transfer`, posilj[2].tok, { email: "nori+1@example.com", allow_guest: true });
    assert(r.status === 200, "nori+1@example.com: 1. prenos", r.status);
    r = await apiD("POST", `/tickets/${posilj[3].vst[1].id}/transfer`, posilj[3].tok, { email: "NORI+drugo@example.com", allow_guest: true });
    assert(r.status === 200, "nori+drugo@example.com: 2. prenos (isti nabiralnik)", r.status);
    r = await apiD("POST", `/tickets/${posilj[4].vst[1].id}/transfer`, posilj[4].tok, { email: "nori@example.com", allow_guest: true });
    assert(r.status === 429, "nori@example.com: 3. prenos na isti nabiralnik (+oznaka obide mejo?) -> 429", r.status);
    r = await apiD("POST", `/tickets/${posilj[4].vst[1].id}/transfer`, posilj[4].tok, { email: "g.m.a.i.l+a@gmail.com", allow_guest: true });
    assert(r.status === 200, "gmail: 1. prenos", r.status);
    r = await apiD("POST", `/tickets/${posilj[5].vst[1].id}/transfer`, posilj[5].tok, { email: "gmail+b@googlemail.com", allow_guest: true });
    assert(r.status === 200, "gmail: 2. prenos (googlemail.com, brez pik)", r.status);
    r = await apiD("POST", `/tickets/${posilj[0].vst[1].id}/transfer`, posilj[0].tok, { email: "gm.ail@gmail.com", allow_guest: true });
    assert(r.status === 429, "gmail: 3. prenos (pike + googlemail) -> 429", r.status);
    // S2: dnevna globalna meja (E): DNEVNO = trenutno stevilo + 1
    const trenutno = (await pool.query("SELECT COUNT(*)::int AS n FROM ticket_transfers WHERE to_guest AND created_at > NOW() - INTERVAL '24 hours'")).rows[0].n;
    const e = zagon(PORT_E, { PRENOS_BREZ_RACUNA: "vsi", GOST_PRENOS_NA_DAN: "1000", GOST_PRENOS_NA_NASLOV: "1000", GOST_PRENOS_DNEVNO: String(trenutno + 1) }); dodatni.push(e);
    await cakajStreznik(E);
    const apiE = (m, p, t, b2, g) => zahtevek(E, m, p, t, b2, g);
    r = await apiE("POST", `/tickets/${posilj[0].vst[0].id}/transfer`, posilj[0].tok, { email: "dnevno1@example.com", allow_guest: true });
    assert(r.status === 200 || r.status === 404, "E: prenos pod dnevno mejo (ali vstopnica ze prenesena)", r.status);
    const prosta = (await kupi(posilj[0].tok, E0, 3));
    r = await apiE("POST", `/tickets/${prosta[0].id}/transfer`, posilj[0].tok, { email: "dnevno2@example.com", allow_guest: true });
    r = await apiE("POST", `/tickets/${prosta[1].id}/transfer`, posilj[0].tok, { email: "dnevno3@example.com", allow_guest: true });
    assert(r.status === 429 && r.body.error === "guest_transfer_limit", "E: nad globalno dnevno mejo gostujocih prenosov: 429", r.body);
    assert(/ALARM: dosezena dnevna meja prenosov/.test(e.log) && !/dnevno[23]@example/.test(e.log), "E: alarm v dnevniku, brez e-naslova", e.log.slice(-200));
    assert((await vstopnica(prosta[1].id)).holder_is_guest === false, "429: vstopnica nespremenjena");
    // S2: posiljatelj brez potrjenega e-naslova (druga plast)
    await pool.query("UPDATE users SET email_verified=FALSE WHERE email='posilj1@outly.si'");
    r = await apiD("POST", `/tickets/${prosta[2].id}/transfer`, posilj[0].tok, { email: "nepotrjen-posiljatelj@example.com", allow_guest: true });
    assert((r.status === 403 && r.body.error === "email_not_verified") || r.status === 200, "posiljatelj z email_verified=false (zahtevek lahko ze pri requireAuth ozdravi vrstico)", r.status);
    await pool.query("UPDATE users SET email_verified=TRUE WHERE email='posilj1@outly.si'");

    // S5: age_confirmed kot niz/stevilo ne zadostuje
    const v18b = await kupi(T.kupec2, E18, 3);
    for (const [vrednost, ime] of [["true", "niz »true«"], [1, "stevilo 1"], ["yes", "niz »yes«"], [null, "null"]]) {
      r = await apiB("POST", `/tickets/${v18b[0].id}/transfer`, T.kupec2, { email: "starost-niz@example.com", allow_guest: true, age_confirmed: vrednost });
      assert(r.status === 400 && r.body.error === "age_confirmation_required", `age_confirmed = ${ime}: 400 age_confirmation_required`, r.body);
    }
    r = await apiB("POST", `/tickets/${v18b[0].id}/transfer`, T.kupec2, { email: "ni-racuna-2@example.com", allow_guest: true, age_confirmed: true });
    assert(r.status === 200, "(izhodisce) age_confirmed true -> 200", r.body);
    // S3: ista 400 za racun z datumom, racun brez datuma, gost
    const odgovori400 = [];
    for (const em of ["racun@outly.si", "brezdatuma@outly.si", "sploh-ni-racuna@example.com"]) {
      r = await apiB("POST", `/tickets/${v18b[1].id}/transfer`, T.kupec2, { email: em, allow_guest: true });
      odgovori400.push(JSON.stringify(r.body));
    }
    assert(odgovori400.every(x => x === odgovori400[0]) && /age_confirmation_required/.test(odgovori400[0]), "S3: 400 age_confirmation_required je IDENTICEN za racun z datumom, racun brez datuma in gosta", odgovori400);
    // S6: nepotrjen racun z vpisanim datumom pod mejo -> 403; brez datuma -> gost 200
    await pool.query("UPDATE users SET email_verified=FALSE, date_of_birth=(CURRENT_DATE - INTERVAL '17 years')::date WHERE email='nepotrjen@outly.si'");
    await pool.query("UPDATE users SET date_of_birth=NULL WHERE email='nepotrjen@outly.si' AND FALSE");
    r = await apiB("POST", `/tickets/${v18b[1].id}/transfer`, T.kupec2, { email: "nepotrjen@outly.si", allow_guest: true, age_confirmed: true });
    assert(r.status === 403 && /at least 18/.test(r.body), "S6: nepotrjen racun z datumom rojstva 17 let, dogodek 18+ -> 403 (znan mladoletnik)", r.body);
    assert((await vstopnica(v18b[1].id)).holder_is_guest === false, "S6: vstopnica nespremenjena");
    // N2: ostanek zetona pred prenosom se izbrise
    await pool.query("INSERT INTO gost_zetoni_vstopnic (token_hash, ticket_id) VALUES ($1, $2)", [hash("ostanek-zetona"), v18b[2].id]);
    r = await apiB("POST", `/tickets/${v18b[2].id}/transfer`, T.kupec2, { email: "n2@example.com", allow_guest: true, age_confirmed: true });
    assert(r.status === 200 && (await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni_vstopnic WHERE token_hash=$1", [hash("ostanek-zetona")])).rows[0].n === 0, "N2: prenos gostu izbrise starejse zetone vstopnice");

    // S5: brezplacen dogodek (cena 0)
    const evProst = (await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, status, ticket_price_cents, capacity, min_age) VALUES (1,'Prenos Prost','https://example.com/p.jpg', NOW() + INTERVAL '2 days', 'published', 0, 50, 0) RETURNING id`)).rows[0].id;
    const pv = await kupi(T.kupec, evProst, 1);
    assert(pv && pv.length === 1, "brezplacen dogodek: nakup (0 EUR) -> vstopnica", pv);
    if (pv && pv.length) {
      r = await apiB("POST", `/tickets/${pv[0].id}/transfer`, T.kupec, { email: "prost@example.com", allow_guest: true });
      assert(r.status === 200, "brezplacna vstopnica: prenos gostu 200", r.body);
      assert(await cakaj(() => poslanoNa("prost@example.com").length === 1), "brezplacna vstopnica: mail s kodo poslan");
      const pz = zetonIzMaila(poslanoNa("prost@example.com")[0]);
      r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": pz });
      assert(r.status === 200 && r.body.ticket.status === "valid", "brezplacna vstopnica: GET /guest/ticket 200 valid", r.status);
    }

    // N3: beli seznam polj GET /guest/ticket
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": z6 });
    const kt6 = r.body.ticket;
    assert(["order_id", "holder_user_id", "holder_id", "holder_email", "is_guest", "order_status"].every(k => !(k in kt6)), "N3: v ticket ni order_id, holder_user_id, holder_id, holder_email, is_guest, order_status", Object.keys(kt6));
    assert(kt6.from_username === "kupec" && kt6.buyer_username === "kupec" && kt6.is_guest_holder === true && kt6.transferred === true && kt6.qr && kt6.serial && kt6.public_ref, "N3: from_username (= buyer_username) = posiljatelj, kljuci, ki jih bere splet, so na voljo", kt6);

    // S4: admin izbris e-naslova (ugovor / zahteva za izbris)
    const prejErase = (await pool.query("SELECT t.id FROM tickets t WHERE t.holder_guest_email = 'ni-racuna-2@example.com'")).rows;
    assert(prejErase.length === 1, "izhodisce: vstopnica z gostom ni-racuna-2@example.com", prejErase);
    await apiB("GET", "/me", T.admin);
    r = await apiB("POST", "/admin/api/guest-tickets/erase", T.kupec2, { email: "ni-racuna-2@example.com" });
    assert(r.status === 403, "erase: navaden uporabnik 403", r.status);
    r = await apiB("POST", "/admin/api/guest-tickets/erase", T.admin, { email: "ni-email" });
    assert(r.status === 400, "erase: neveljaven naslov 400", r.status);
    // zeton obstaja (mail ga je skoval)
    assert(await cakaj(() => poslanoNa("ni-racuna-2@example.com").length === 1), "(izhodisce) mail gostu poslan");
    const zE = zetonIzMaila(poslanoNa("ni-racuna-2@example.com")[0]);
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": zE });
    assert(r.status === 200, "(izhodisce) zeton pred izbrisom velja");
    r = await apiB("POST", "/admin/api/guest-tickets/erase", T.admin, { email: " Ni-Racuna-2@Example.com " });
    assert(r.status === 200 && r.body.tickets === 1 && r.body.transfers >= 1, "erase: admin izbrise e-naslov (stevili)", r.body);
    const po = await vstopnica(prejErase[0].id);
    assert(po.holder_guest_email === null && po.holder_is_guest === true, "erase: holder_guest_email NULL, vstopnica ostane gostujoca", po);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni_vstopnic WHERE ticket_id=$1", [prejErase[0].id])).rows[0].n === 0, "erase: zetoni izbrisani");
    r = await apiB("GET", "/guest/ticket", null, undefined, { "x-guest-token": zE });
    assert(r.status === 404, "erase: povezava ne deluje vec (404)");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM ticket_transfers WHERE to_email = 'ni-racuna-2@example.com'")).rows[0].n === 0, "erase: to_email v zapisih prenosa anonimiziran");
    r = await apiB("POST", "/admin/api/guest-tickets/erase", T.admin, { email: "ni-racuna-2@example.com" });
    assert(r.status === 200 && r.body.tickets === 0 && r.body.transfers === 0, "erase: ponovitev je idempotentna (0, 0)", r.body);

    // S1: zanka dogodkov med navalom sestavljanja mailov (modul vstopnica_priloge.js neposredno): 40 hkratnih »mailov« s 6 vstopnicami
    const { qrPng: qrPngT, pdfVstopnice: pdfT } = require("../vstopnica_priloge");
    const kod = () => "o2." + crypto.randomBytes(100).toString("base64url") + "." + crypto.randomBytes(64).toString("base64url");
    const eno = async () => {
      const ks = Array.from({ length: 6 }, kod);
      await qrPngT(ks[0]);
      await pdfT({ dogodek: { naslov: "Noc", zacetek: "x", prizoriscePodatki: "y", starost: "", organizator: "" }, vstopnice: ks.map(k => ({ koda: k, vrsta: "S", oznaka: "t" })), varnost: "v" });
    };
    await Promise.all(Array.from({ length: 4 }, eno));   // ogrevanje (JIT)
    const zamiki = []; let zadnji = process.hrtime.bigint();
    const casovnik = setInterval(() => { const n = process.hrtime.bigint(); zamiki.push(Number(n - zadnji) / 1e6 - 1); zadnji = n; }, 1);
    const t0 = Date.now();
    await Promise.all(Array.from({ length: 40 }, eno));
    clearInterval(casovnik);
    zamiki.sort((x, y) => x - y);
    const p99 = zamiki[Math.floor(zamiki.length * 0.99)], najvec = zamiki[zamiki.length - 1];
    console.log(`  (40 x 6 vstopnic: ${Date.now() - t0} ms skupaj; zamik zanke p50 ${zamiki[zamiki.length >> 1].toFixed(1)} p99 ${p99.toFixed(1)} max ${najvec.toFixed(1)} ms)`);
    assert(p99 < 30, "S1: p99 zamika zanke dogodkov med navalom sestavljanja QR + PDF < 30 ms", p99);
    // N1: predolgo besedilo ne potisne kode QR s strani
    const dolg = await pdfT({ dogodek: { naslov: "N".repeat(3000), zacetek: "x", prizoriscePodatki: "P".repeat(3000), starost: "", organizator: "O".repeat(3000) }, vstopnice: [{ koda: kod(), vrsta: "S", oznaka: "" }], varnost: "v" });
    const dolgS = dolg.toString("latin1");
    assert(dolg.length < 80000 && dolgS.includes("\x85") && (dolgS.match(/ re f/g) || []).length > 100 && !dolgS.includes("N".repeat(130)), "N1: PDF z 3000-znakovnim naslovom: skrajsan (…), koda QR na strani", dolg.length);

    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    const napake = (a.log + b.log + c.log).split("\n").filter(l => /TypeError|Unhandled|ReferenceError|error: /i.test(l) && !/Resend napaka/.test(l) && !/stub/.test(l));
    if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.slice(0, 20).join("\n"));
  } finally {
    for (const s of [a, b, c, ...dodatni]) s.srv.kill();
    jwksServer.close(); resendServer.close(); await pool.end();
  }
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
