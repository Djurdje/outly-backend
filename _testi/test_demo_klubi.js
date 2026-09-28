#!/usr/bin/env node
/**
 * Test: migracija 022_demo_klubi.sql na bazi s podatki.
 * Klub z najvec dogodki -> Velvet, nato Nexus, Mirage, Mansion, Olie; 6. klub nespremenjen.
 * Vsak preimenovan klub ima po migraciji vsaj 3 koncane in vsaj 3 prihajajoce objavljene dogodke;
 * obstojeci dogodki, narocila in vstopnice ostanejo. Drugi zagon ne doda nicesar.
 * Zagon (lokalno, PG16, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_demo_klubi.js
 * Nato migracija 023: Velvet..Olie dobijo logotip z outly.si/assets/clubs, 6. klub ne.
 * Backend na 3121 (brez prijave - samo javne poti).
 */
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3121;
const BASE = `http://127.0.0.1:${PORT}`;

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(p) {
  const r = await fetch(BASE + p);
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

// Isto kot migrate.js: brez vrstic BEGIN;/COMMIT; (zavijemo sami).
const brezTransakcije = (ime) => fs.readFileSync(path.join(__dirname, "..", "db", "migracije", ime), "utf8")
  .split("\n").filter(v => !/^\s*(BEGIN|COMMIT)\s*;\s*$/i.test(v)).join("\n");
const SQL = brezTransakcije("022_demo_klubi.sql");
const SQL_LOGOTIPI = brezTransakcije("023_logotipi_demo_klubov.sql");

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");

  // 6 lastnikov in 6 klubov s pravimi imeni (kot demo v produkciji).
  for (let i = 1; i <= 6; i++) {
    await pool.query("INSERT INTO users (email, username, role, email_verified) VALUES ($1, $2, 'business', TRUE)", [`l${i}@outly.si`, `lastnik${i}`]);
  }
  const imena = ["Cirkus", "K4", "Cvetlicarna", "Square", "Nebo", "Sesti"];
  for (let i = 0; i < 6; i++) {
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, genres, bar_prices) VALUES ($1, $2, 'Ljubljana', $3, $4::jsonb)",
      [i + 1, imena[i], i === 1 ? ["techno"] : [], i === 2 ? JSON.stringify([{ name: "Pivo", price_cents: 400 }]) : "[]"]);
  }
  // Stevilo dogodkov: K4 (id 2) 5, Cirkus (1) 4, Square (4) 3, Cvetlicarna (3) 1, Nebo (5) 1, Sesti (6) 0.
  // Pricakovan vrstni red: 2 Velvet, 1 Nexus, 4 Mirage, 3 Mansion (1 dogodek, manjsi id), 5 Olie.
  const dogodki = [
    [2, "K4 pretekli A", "-3 days", 50], [2, "K4 pretekli B", "-10 days", 20], [2, "K4 pretekli C", "-20 days", 5],
    [2, "K4 pretekli D", "-30 days", 1], [2, "K4 prihodnji", "+5 days", 0],
    [1, "Cirkus prihodnji A", "+3 days", 0], [1, "Cirkus prihodnji B", "+40 days", 0], [1, "Cirkus prihodnji C", "+60 days", 0],
    [1, "Cirkus prihodnji D", "+90 days", 0],
    [4, "Square pretekli", "-2 days", 10], [4, "Square prihodnji", "+7 days", 0], [4, "Square pretekli 2", "-4 days", 3],
    [3, "Cvet prihodnji", "+14 days", 0],
    [5, "Nebo pretekli", "-6 days", 7],
  ];
  for (const [cid, t, pomik, prodanih] of dogodki) {
    await pool.query(`INSERT INTO events (club_id, title, poster_url, start_at, status, capacity, sold_count)
      VALUES ($1, $2, 'https://example.com/p.jpg', NOW() + $3::interval, 'published', 100, $4)`, [cid, t, pomik, prodanih]);
  }
  // Narocilo in vstopnica na K4 - morata ostati.
  const eid = (await pool.query("SELECT id FROM events WHERE title='K4 pretekli A'")).rows[0].id;
  await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
    VALUES ('OUT-TEST1', 1, $1, 2, 1, 1000, 1000, 'paid', 'l1@outly.si', NOW())`, [eid]);
  await pool.query("INSERT INTO tickets (order_id, event_id, status) VALUES ((SELECT id FROM orders WHERE public_ref='OUT-TEST1'), $1, 'valid')", [eid]);
  const predDogodkov = (await pool.query("SELECT COUNT(*)::int AS n FROM events")).rows[0].n;

  console.log("\n# Migracija 022 na bazi s podatki");
  await pool.query("BEGIN"); await pool.query(SQL); await pool.query("COMMIT");

  const klubi = (await pool.query("SELECT * FROM clubs ORDER BY id")).rows;
  const ime = Object.fromEntries(klubi.map(c => [c.id, c.name]));
  assert(ime[2] === "Velvet", "klub z najvec dogodki (K4) -> Velvet", ime);
  assert(ime[1] === "Nexus" && ime[4] === "Mirage" && ime[3] === "Mansion" && ime[5] === "Olie", "ostali po stevilu dogodkov: Nexus, Mirage, Mansion, Olie", ime);
  assert(ime[6] === "Sesti", "6. klub ostane nespremenjen", ime[6]);

  for (const c of klubi.filter(c => c.id <= 5)) {
    const polna = c.description.length > 50 && c.contact_phone.startsWith("+386") && c.contact_email.endsWith("@example.com")
      && c.instagram && c.address && c.city === "Ljubljana" && c.country === "Slovenia";
    assert(polna, `${c.name}: opis, telefon, e-naslov, instagram, naslov, mesto, drzava`, c);
    assert(c.lat > 46.045 && c.lat < 46.058 && c.lng > 14.498 && c.lng < 14.512, `${c.name}: koordinate v centru Ljubljane`, [c.lat, c.lng]);
    assert(c.genres.includes("balkan"), `${c.name}: zanr balkan`, c.genres);
    assert(Array.isArray(c.bar_prices) && c.bar_prices.length > 0, `${c.name}: cenik bara`, c.bar_prices);
    const st = (await pool.query(`SELECT
        COUNT(*) FILTER (WHERE COALESCE(end_at, start_at + INTERVAL '8 hours') <= NOW())::int AS koncani,
        COUNT(*) FILTER (WHERE start_at > NOW())::int AS prihodnji,
        MAX(start_at) AS zadnji
      FROM events WHERE club_id=$1 AND status='published'`, [c.id])).rows[0];
    assert(st.koncani >= 3 && st.prihodnji >= 3, `${c.name}: >= 3 koncani in >= 3 prihajajoci`, st);
    assert(new Date(st.zadnji) < new Date("2027-03-15T00:00:00Z"), `${c.name}: zadnji dogodek najkasneje v ~5 mesecih`, st.zadnji);
  }
  assert(klubi.find(c => c.id === 2).genres.includes("techno"), "obstojeci zanr (techno) ostane", klubi.find(c => c.id === 2).genres);
  assert(klubi.find(c => c.id === 3).bar_prices.length === 1, "obstojeci cenik ostane nespremenjen", klubi.find(c => c.id === 3).bar_prices);
  const novi = (await pool.query("SELECT poster_url, sold_count, capacity FROM events WHERE title LIKE '% @ %'")).rows;
  assert(novi.length > 0 && novi.every(e => e.poster_url === "https://example.com/p.jpg"), "novi dogodki dobijo obstojeci plakat kluba", novi.slice(0, 2));
  assert(novi.every(e => e.sold_count <= e.capacity), "sold_count <= capacity");
  // Cirkus (Nexus) je imel 4 prihodnje -> ne dobi novih prihodnjih.
  const nexusNovihPrihodnjih = (await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE club_id=1 AND start_at > NOW() AND title LIKE '% @ %'")).rows[0].n;
  assert(nexusNovihPrihodnjih === 0, "klub z dovolj prihajajocimi ne dobi novih", nexusNovihPrihodnjih);
  const t = (await pool.query("SELECT (SELECT COUNT(*) FROM orders)::int AS o, (SELECT COUNT(*) FROM tickets)::int AS t, (SELECT COUNT(*) FROM events WHERE title NOT LIKE '% @ %')::int AS e")).rows[0];
  assert(t.o === 1 && t.t === 1 && t.e === predDogodkov, "narocila, vstopnice in obstojeci dogodki ostanejo", t);

  console.log("\n# Drugi zagon ne doda nicesar");
  const n1 = (await pool.query("SELECT COUNT(*)::int AS n FROM events")).rows[0].n;
  await pool.query("BEGIN"); await pool.query(SQL); await pool.query("COMMIT");
  const n2 = (await pool.query("SELECT COUNT(*)::int AS n FROM events")).rows[0].n;
  assert(n1 === n2, "stevilo dogodkov enako po drugem zagonu", [n1, n2]);

  console.log("\n# Migracija 023: logotipi");
  await pool.query("UPDATE clubs SET logo_url='https://example.com/star.png'");
  await pool.query("BEGIN"); await pool.query(SQL_LOGOTIPI); await pool.query("COMMIT");
  const logo = Object.fromEntries((await pool.query("SELECT name, logo_url FROM clubs")).rows.map(r => [r.name, r.logo_url]));
  for (const [ime, dat] of [["Velvet", "velvet"], ["Nexus", "nexus"], ["Mirage", "mirage"], ["Mansion", "mansion"], ["Olie", "olie"]]) {
    assert(logo[ime] === `https://outly.si/assets/clubs/${dat}.jpg`, `${ime}: logotip ${dat}.jpg`, logo[ime]);
  }
  assert(logo["Sesti"] === "https://example.com/star.png", "6. klub ohrani svoj logotip", logo["Sesti"]);

  console.log("\n# Javne poti");
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: "http://127.0.0.1:1", RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
  let r = await api("/clubs");
  const seznam = Array.isArray(r.body) ? r.body : (r.body.clubs || []);
  assert(r.status === 200 && seznam.some(c => c.name === "Velvet" && c.contact_phone === "+386 1 620 41 10"), "GET /clubs vrne Velvet s telefonom", r.status);
  const velvet = seznam.find(c => c.name === "Velvet") || {};
  assert((velvet.logo_url ?? velvet.logoUrl) === "https://outly.si/assets/clubs/velvet.jpg", "GET /clubs vrne Velvetov logotip", velvet.logo_url ?? velvet.logoUrl);
  for (const id of [1, 2, 3, 4, 5]) {
    r = await api(`/events?clubId=${id}&popular=true`);
    assert(r.status === 200 && r.body.length === 3, `GET /events?clubId=${id}&popular=true -> 3`, r.body.length);
    r = await api(`/events?clubId=${id}&upcoming=true`);
    assert(r.status === 200 && r.body.length >= 3, `GET /events?clubId=${id}&upcoming=true -> >= 3`, r.body.length);
  }

  srv.kill();
  await pool.query("TRUNCATE club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await pool.end();
  console.log(`\n${ok} ok, ${fail} napak`);
  if (fail) { console.log(log.slice(-2000)); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
