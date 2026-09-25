#!/usr/bin/env node
/**
 * Test "Check activity" na nadzorni plosci kluba (migracija 021, Martin 25. 9. 2026):
 * POST /views, GET /business/activity, GET /business/team/:userId/scans,
 * GET /business/sales?range=week|month|year (series) + events[].interested_count.
 * Vzorec kot test_vstopnice.js / test_zanimanje.js: lokalni JWKS, backend na svojem portu.
 * Zagon (lokalno, PG16, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_aktivnost.js
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3118, JWKS_PORT = 3997;
const BASE = `http://127.0.0.1:${PORT}`;

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
async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE view_counts, event_interest, club_event_notifications, club_follows, club_invites, club_members, event_favorites, friendships, friend_requests, ticket_transfers, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    manager: zeton("manager@outly.si", uuid(2)),
    doorman: zeton("doorman@outly.si", uuid(3)),
    ana: zeton("ana@outly.si", uuid(4)),
    tujec: zeton("tujec@outly.si", uuid(5)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  const id = {};
  for (const row of (await pool.query("SELECT id, email FROM users")).rows) id[row.email.split("@")[0]] = row.id;

  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Pure Club', 'Ljubljana')", [id.lastnik]);
  await pool.query("INSERT INTO clubs (owner_user_id, name, city, hidden) VALUES ($1, 'Skriti Klub', 'Maribor', TRUE)", [id.lastnik]);
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, $1, 'manager')", [id.manager]);
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, $1, 'doorman')", [id.doorman]);
  const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  await api("PATCH", "/me", T.ana, { dateOfBirth: polnoleten });

  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Zabava", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  assert(r.status === 201, "dogodek ustvarjen", r.body);
  const dogodek = r.body.id;
  const skritDogodekR = await pool.query("INSERT INTO events (club_id, title, start_at, min_age) VALUES (2, 'v skritem klubu', NOW() + INTERVAL '1 day', 0) RETURNING id");
  const skritDogodek = skritDogodekR.rows[0].id;

  console.log("\n# POST /views — profil in dogodek");
  r = await api("POST", "/views", null, { club_id: 1 });
  assert(r.status === 204, "ogled profila -> 204", r.status);
  r = await api("POST", "/views", null, { club_id: 1 });
  assert(r.status === 204, "ponoven ogled profila isti dan -> 204", r.status);
  r = await api("POST", "/views", null, { event_id: dogodek });
  assert(r.status === 204, "ogled dogodka -> 204", r.status);

  let vc = await pool.query("SELECT club_id, event_id, count FROM view_counts WHERE club_id=1 AND event_id IS NULL");
  assert(vc.rows.length === 1 && vc.rows[0].count === 2, "profil kluba 1: en zapis, stevec 2 (dva klica isti dan)", vc.rows);
  vc = await pool.query("SELECT club_id, event_id, count FROM view_counts WHERE event_id=$1", [dogodek]);
  assert(vc.rows.length === 1 && vc.rows[0].count === 1 && vc.rows[0].club_id === 1, "dogodek: en zapis, stevec 1, club_id prevzet iz dogodka", vc.rows);

  r = await api("POST", "/views", null, { club_id: 2 });
  assert(r.status === 204, "ogled skritega kluba -> 204 (tiho)", r.status);
  vc = await pool.query("SELECT COUNT(*)::int AS n FROM view_counts WHERE club_id=2");
  assert(vc.rows[0].n === 0, "skrit klub se NE steje (brez zapisa)", vc.rows[0]);

  r = await api("POST", "/views", null, { event_id: skritDogodek });
  assert(r.status === 204, "ogled dogodka v skritem klubu -> 204 (tiho)", r.status);
  vc = await pool.query("SELECT COUNT(*)::int AS n FROM view_counts WHERE event_id=$1", [skritDogodek]);
  assert(vc.rows[0].n === 0, "dogodek skritega kluba se NE stejе", vc.rows[0]);

  r = await api("POST", "/views", null, { club_id: 999999 });
  assert(r.status === 204, "neobstojec club_id -> 204 (tiho)", r.status);
  r = await api("POST", "/views", null, { event_id: 999999 });
  assert(r.status === 204, "neobstojec event_id -> 204 (tiho)", r.status);
  r = await api("POST", "/views", null, {});
  assert(r.status === 204, "brez club_id in event_id -> 204 (tiho)", r.status);
  vc = await pool.query("SELECT COUNT(*)::int AS n FROM view_counts");
  assert(vc.rows[0].n === 2, "skupaj samo 2 veljavna zapisa (profil kluba 1 + dogodek)", vc.rows[0]);

  // Star ogled (izven zadnjih 7 dni), da locimo skupno stevilo od _7d.
  await pool.query("INSERT INTO view_counts (club_id, event_id, day, count) VALUES (1, NULL, CURRENT_DATE - INTERVAL '10 days', 5)");
  await pool.query("INSERT INTO view_counts (club_id, event_id, day, count) VALUES (1, $1, CURRENT_DATE - INTERVAL '10 days', 3)", [dogodek]);

  console.log("\n# GET /business/activity — dostop");
  r = await api("GET", "/business/activity");
  assert(r.status === 401, "brez zetona -> 401", r.status);
  r = await api("GET", "/business/activity", T.tujec);
  assert(r.status === 403, "uporabnik brez kluba -> 403", r.status);
  r = await api("GET", "/business/activity", T.doorman);
  assert(r.status === 403, "vratar ne sme videti aktivnosti -> 403", r.status);

  console.log("\n# GET /business/tickets/scan tok, da imamo skene za aktivnost");
  const dogodekVstopnice = await pool.query("SELECT id, serial FROM tickets WHERE event_id=$1", [dogodek]);
  r = await api("POST", `/events/${dogodek}/orders`, T.ana, { quantity: 3 });
  assert(r.status === 201, "ana kupi 3 vstopnice", r.body);
  const vstopnice = (await pool.query("SELECT id, serial FROM tickets WHERE event_id=$1 ORDER BY id", [dogodek])).rows;
  assert(vstopnice.length === 3, "3 vstopnice ustvarjene", vstopnice.length);

  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: vstopnice[0].serial });
  assert(r.status === 200, "lastnik skenira vstopnico 1", r.body);
  r = await api("POST", "/business/tickets/scan", T.manager, { serial: vstopnice[1].serial });
  assert(r.status === 200, "manager skenira vstopnico 2", r.body);
  r = await api("POST", "/business/tickets/scan", T.manager, { serial: vstopnice[2].serial });
  assert(r.status === 200, "manager skenira vstopnico 3", r.body);

  console.log("\n# GET /business/activity — vsebina");
  r = await api("GET", "/business/activity", T.lastnik);
  assert(r.status === 200, "lastnik -> 200", r.body);
  assert(r.body.clicks_profile === 7, "clicks_profile = 2 + 5 (star ogled)", r.body.clicks_profile);
  assert(r.body.clicks_profile_7d === 2, "clicks_profile_7d = samo 2 (star ogled izpade)", r.body.clicks_profile_7d);
  assert(r.body.clicks_events === 4, "clicks_events = 1 + 3 (star ogled)", r.body.clicks_events);
  assert(r.body.clicks_events_7d === 1, "clicks_events_7d = samo 1", r.body.clicks_events_7d);
  assert(r.body.followers_count === 0, "followers_count = 0 (nihce ne sledi)", r.body.followers_count);

  await pool.query("INSERT INTO club_follows (club_id, user_id) VALUES (1, $1)", [id.ana]);
  await pool.query("INSERT INTO club_follows (club_id, user_id, created_at) VALUES (1, $1, NOW() - INTERVAL '20 days')", [id.tujec]);
  r = await api("GET", "/business/activity", T.manager);
  assert(r.status === 200, "manager -> 200 (sme videti)", r.body);
  assert(r.body.followers_count === 2, "followers_count = 2", r.body.followers_count);
  assert(r.body.followers_new_7d === 1, "followers_new_7d = 1 (samo ana, tujec je star 20 dni)", r.body.followers_new_7d);

  const staff = r.body.staff;
  assert(Array.isArray(staff) && staff.length === 3, "staff: lastnik + manager + doorman (3)", staff);
  const lastnikStaff = staff.find(s => s.id === id.lastnik);
  const managerStaff = staff.find(s => s.id === id.manager);
  const doormanStaff = staff.find(s => s.id === id.doorman);
  assert(lastnikStaff && lastnikStaff.role === "owner" && lastnikStaff.scans === 1, "lastnik: role owner, 1 sken", lastnikStaff);
  assert(managerStaff && managerStaff.role === "manager" && managerStaff.scans === 2, "manager: role manager, 2 skena", managerStaff);
  assert(doormanStaff && doormanStaff.role === "doorman" && doormanStaff.scans === 0, "doorman: 0 skenov", doormanStaff);
  assert(staff[0].id === id.manager, "staff urejen po scans DESC (manager prvi z 2)", staff.map(s => [s.id, s.scans]));

  console.log("\n# GET /business/team/:userId/scans");
  r = await api("GET", `/business/team/${id.manager}/scans`, T.lastnik);
  assert(r.status === 200 && Array.isArray(r.body.events) && r.body.events.length === 1, "manager: 1 dogodek s skeni", r.body);
  assert(r.body.events[0].id === dogodek && r.body.events[0].scans === 2, "dogodek Zabava, 2 skena", r.body.events[0]);
  r = await api("GET", `/business/team/${id.doorman}/scans`, T.lastnik);
  assert(r.status === 200 && r.body.events.length === 0, "doorman: brez dogodkov (0 skenov se ne kaze)", r.body);
  r = await api("GET", `/business/team/${id.tujec}/scans`, T.lastnik);
  assert(r.status === 404, "oseba, ki ni v ekipi -> 404", r.status);
  r = await api("GET", `/business/team/${id.manager}/scans`, T.doorman);
  assert(r.status === 403, "vratar ne sme klicati te poti -> 403", r.status);
  r = await api("GET", `/business/team/${id.manager}/scans`);
  assert(r.status === 401, "brez zetona -> 401", r.status);

  console.log("\n# GET /business/sales?range=... — series in interested_count");
  r = await api("GET", "/business/sales", T.lastnik);
  assert(r.status === 200 && r.body.series === undefined && Array.isArray(r.body.sales_by_day) && r.body.sales_by_day.length === 14,
    "brez range: kot doslej (sales_by_day 14 dni, brez series)", { series: r.body.series, dni: r.body.sales_by_day && r.body.sales_by_day.length });

  r = await api("GET", "/business/sales?range=week", T.lastnik);
  assert(r.status === 200 && Array.isArray(r.body.series) && r.body.series.length === 7, "range=week -> 7 kosov", r.body.series && r.body.series.length);
  assert(r.body.series.every(s => /^\d{4}-\d{2}-\d{2}$/.test(s.bucket)), "week: bucket YYYY-MM-DD", r.body.series);

  r = await api("GET", "/business/sales?range=month", T.lastnik);
  assert(r.status === 200 && Array.isArray(r.body.series) && r.body.series.length === 30, "range=month -> 30 kosov", r.body.series && r.body.series.length);

  r = await api("GET", "/business/sales?range=year", T.lastnik);
  assert(r.status === 200 && Array.isArray(r.body.series) && r.body.series.length === 12, "range=year -> 12 kosov", r.body.series && r.body.series.length);
  assert(r.body.series.every(s => /^\d{4}-\d{2}$/.test(s.bucket)), "year: bucket YYYY-MM", r.body.series);
  const skupajTicketi = r.body.series.reduce((a, s) => a + s.tickets, 0);
  assert(skupajTicketi === 3, "leto: skupaj 3 vstopnice (vsota po mesecih)", skupajTicketi);

  await api("PUT", `/events/${dogodek}/interest`, T.ana);
  r = await api("GET", "/business/sales", T.lastnik);
  const dogodekVSales = r.body.events.find(e => e.id === dogodek);
  assert(dogodekVSales && dogodekVSales.interested_count === 1, "events[].interested_count = 1 (ana oznacila I'm in)", dogodekVSales);

  console.log(`\n${ok} v redu, ${fail} padlo.`);
  srv.kill();
  await pool.end();
  jwksServer.close();
  if (fail > 0) { console.log(log); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
