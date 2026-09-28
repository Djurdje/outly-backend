#!/usr/bin/env node
/**
 * Test migracije 022 (izmisljeni demo klubi namesto pravih ljubljanskih). Zagon na bazi z vsemi migracijami:
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_demo_klubi.js
 * Samo baza, brez backenda: napolni stare demo klube (kot v produkciji), ponovno pozene telo 022
 * in preveri, da so klubi prepisani, dogodki brez vstopnic zamenjani, dogodek z vstopnico pa ohranjen.
 */
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const pool = new Pool({ connectionString: DB, ssl: DB.includes("localhost") ? false : { rejectUnauthorized: false } });

// Isto kot db/migrate.js: brez vrstic BEGIN;/COMMIT;
const SQL = fs.readFileSync(path.join(__dirname, "..", "db", "migracije", "022_izmisljeni_demo_klubi.sql"), "utf8")
  .split("\n").filter((v) => !/^\s*(BEGIN|COMMIT)\s*;\s*$/i.test(v)).join("\n");

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

async function pocisti(c) {
  await c.query("TRUNCATE tickets, orders, event_favorites, event_interest, club_event_notifications, view_counts, events, club_follows, club_members, club_invites, clubs RESTART IDENTITY CASCADE");
  await c.query("DELETE FROM users WHERE email LIKE '%@test022.si'");
}

async function napolni(c) {
  const lastnik = (await c.query(
    "INSERT INTO users (email, username, role) VALUES ('lastnik@test022.si', 'lastnik022', 'business') RETURNING id")).rows[0].id;
  const kupec = (await c.query(
    "INSERT INTO users (email, username) VALUES ('gost@test022.si', 'gost022') RETURNING id")).rows[0].id;
  const imena = ["Cirkus", "Klub K4", "Cvetličarna", "Square", "Nebo", "Kinodvor"];
  const ids = {};
  for (const ime of imena) {
    ids[ime] = (await c.query(
      "INSERT INTO clubs (owner_user_id, name, logo_url, instagram, website, contact_phone) VALUES ($1, $2, 'https://pravi-klub.si/logo.png', '@pravi', 'https://pravi-klub.si', '+386 1 234 56 78') RETURNING id",
      [lastnik, ime])).rows[0].id;
    for (let i = 0; i < 3; i++) {
      await c.query("INSERT INTO events (club_id, title, start_at, poster_url) VALUES ($1, $2, NOW() + interval '3 days', 'https://pravi-klub.si/p.jpg')",
        [ids[ime], `${ime} stari dogodek ${i}`]);
    }
  }
  // Na enem dogodku K4 je kupljena vstopnica (RESTRICT) - mora ostati, z novim naslovom.
  const ev = (await c.query("SELECT id FROM events WHERE club_id = $1 ORDER BY id LIMIT 1", [ids["Klub K4"]])).rows[0].id;
  const o = (await c.query(
    `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
     VALUES ('T022', $1, $2, $3, 1, 1000, 1000, 'paid', 'gost@test022.si', NOW()) RETURNING id`, [kupec, ev, ids["Klub K4"]])).rows[0].id;
  await c.query("INSERT INTO tickets (order_id, event_id, holder_user_id) VALUES ($1, $2, $3)", [o, ev, kupec]);
  await c.query("INSERT INTO club_follows (club_id, user_id) VALUES ($1, $2)", [ids["Cirkus"], kupec]);
  return { ids, ev, kupec };
}

(async () => {
  const c = await pool.connect();
  try {
    console.log("022: prazna baza (brez klubov) ne naredi nic");
    await pocisti(c);
    await c.query(SQL);
    assert((await c.query("SELECT COUNT(*)::int n FROM events")).rows[0].n === 0, "brez klubov ni novih dogodkov");

    console.log("022: stari demo klubi -> izmisljeni");
    await pocisti(c);
    const { ids, ev } = await napolni(c);
    await c.query(SQL);

    const klubi = (await c.query("SELECT * FROM clubs ORDER BY id")).rows;
    const po = Object.fromEntries(klubi.map((k) => [k.id, k]));
    const pricakovano = { "Cirkus": "Orbita", "Klub K4": "HALOGEN", "Cvetličarna": "Kovačnica", "Square": "Bazen", "Nebo": "Nocturne" };
    for (const [staro, novo] of Object.entries(pricakovano)) {
      const k = po[ids[staro]];
      assert(k.name === novo, `${staro} -> ${novo} (isti id)`, k.name);
      assert(k.logo_url.startsWith("https://outly.si/demo/") && k.banner_url.startsWith("https://outly.si/demo/"), `${novo}: logo in banner na outly.si/demo`);
      assert(k.gallery_urls.length === 3 && k.video_url.endsWith(".mp4"), `${novo}: 3 slike galerije + video`);
      assert(k.instagram === "" && k.website === "" && k.contact_phone === "", `${novo}: brez tujih povezav (instagram, splet, telefon)`);
      assert(k.description.length > 200 && k.lat !== null && k.genres.length > 0, `${novo}: opis, koordinate, zanri`);
      const cenik = k.bar_prices;
      assert(Array.isArray(cenik) && cenik.length >= 10 && cenik.length <= 60
        && cenik.every((p) => p.name.length >= 1 && p.name.length <= 60 && Number.isInteger(p.price_cents) && p.price_cents >= 0 && p.price_cents <= 100000
          && (p.category === undefined || p.category.length <= 30)),
        `${novo}: cenik bara ustreza preveriCenik (index.js)`);
      const dog = (await c.query("SELECT title, poster_url, start_at, status FROM events WHERE club_id = $1 ORDER BY start_at", [k.id])).rows;
      const novi = dog.filter((d) => d.poster_url.includes("/events/"));
      assert(novi.length === 3 && novi.every((d) => d.status === "published"), `${novo}: 3 novi objavljeni dogodki`, dog.map((d) => d.title));
      assert(!dog.some((d) => d.title.includes("stari dogodek")), `${novo}: starih naslovov ni vec`);
    }
    assert(po[ids["Kinodvor"]].name === "Kinodvor" && po[ids["Kinodvor"]].instagram === "@pravi", "drug klub (Kinodvor) nedotaknjen");
    assert((await c.query("SELECT COUNT(*)::int n FROM events WHERE club_id = $1", [ids["Kinodvor"]])).rows[0].n === 3, "dogodki drugega kluba nedotaknjeni");

    const ohranjen = (await c.query("SELECT title, poster_url FROM events WHERE id = $1", [ev])).rows[0];
    assert(ohranjen && ohranjen.title === "HALOGEN Session" && ohranjen.poster_url.startsWith("https://outly.si/demo/halogen/"),
      "dogodek z vstopnico ohranjen, prepisan naslov in plakat", ohranjen);
    assert((await c.query("SELECT COUNT(*)::int n FROM tickets WHERE event_id = $1 AND status = 'valid'", [ev])).rows[0].n === 1, "vstopnica ostane veljavna");
    assert((await c.query("SELECT COUNT(*)::int n FROM club_follows WHERE club_id = $1", [ids["Cirkus"]])).rows[0].n === 1, "sledilci ostanejo");

    console.log("022: ponoven zagon ne podvoji");
    const pred = (await c.query("SELECT COUNT(*)::int n FROM events")).rows[0].n;
    await c.query(SQL);
    assert((await c.query("SELECT COUNT(*)::int n FROM events")).rows[0].n === pred, "stevilo dogodkov enako");

    console.log("022: dvoumno ime -> migracija pade, nic se ne spremeni");
    await pocisti(c);
    const l = (await c.query("INSERT INTO users (email, username, role) VALUES ('l2@test022.si', 'l2022', 'business') RETURNING id")).rows[0].id;
    await c.query("INSERT INTO clubs (owner_user_id, name) VALUES ($1, 'Cirkus'), ($1, 'Cirkus Maribor')", [l]);
    let napaka = null;
    try { await c.query("BEGIN"); await c.query(SQL); await c.query("COMMIT"); } catch (e) { napaka = e; await c.query("ROLLBACK"); }
    assert(napaka && /ustreza 2 klubom/.test(napaka.message), "napaka ob dveh Cirkusih", napaka && napaka.message);
    assert((await c.query("SELECT COUNT(*)::int n FROM clubs WHERE name LIKE 'Cirkus%'")).rows[0].n === 2, "klubi nespremenjeni");

    await pocisti(c);
  } finally {
    c.release();
    await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
