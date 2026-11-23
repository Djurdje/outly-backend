#!/usr/bin/env node
/**
 * Migracija 078: vpis OBSTOJECIH racunov v uradni profil Outly (DECISIONS 2026-11-22; 2. korak za 077).
 * Zagon: DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_vpis_uradni_078.js
 * Brez strezniskega procesa (samo SQL): vrstice za vse pare (racun, uradni klub), viden in ne demo, s samodejno = TRUE; obstojeca izbrana vrstica (FALSE)
 * ostane; brez obvestil; ponovni zagon ne naredi nic; brez uradnega kluba nic; migracija ne vsebuje ALTER/UPDATE/DELETE.
 * Obnasanje push/zvonec samodejnih sledilcev testira test_samodejno_sledenje.js (077 + koda).
 */
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

(async () => {
  const pool = new Pool({ connectionString: DB });
  const n = async (sql, p) => (await pool.query(sql, p)).rows[0].n;
  try {
    await pool.query("TRUNCATE omejitve, club_event_notifications, club_follows, club_invites, club_members, event_favorites, friendships, friend_requests, ticket_transfers, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
    const sql = fs.readFileSync(path.join(__dirname, "..", "db", "migracije", "078_samodejno_vpis_uradni.sql"), "utf8");
    assert(!/\b(ALTER|UPDATE|DELETE)\b/i.test(sql.replace(/^--.*$/gm, "")), "078 ne vsebuje ALTER/UPDATE/DELETE (samo INSERT ... ON CONFLICT DO NOTHING)");

    console.log("\n# Brez uradnega kluba migracija ne naredi nic");
    await pool.query("INSERT INTO users (email, username, email_verified) VALUES ('a@outly.si','a',true), ('b@outly.si','b',true)");
    await pool.query(sql);
    assert((await n("SELECT COUNT(*)::int AS n FROM club_follows")) === 0, "brez uradnega kluba 0 vrstic");

    console.log("\n# Uradni klub: vsi racuni, samodejno = TRUE; skriti in demo ne; izbrana vrstica ostane");
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, is_official, hidden, is_demo) VALUES
      (1, 'Outly', 'Ljubljana', TRUE, FALSE, FALSE), (1, 'Navaden', 'Ljubljana', FALSE, FALSE, FALSE),
      (1, 'Skriti uradni', 'Maribor', TRUE, TRUE, FALSE), (1, 'Demo uradni', 'Maribor', TRUE, FALSE, TRUE)`);
    await pool.query("INSERT INTO users (email, username, email_verified) VALUES ('c@outly.si','c',true), ('d@outly.si','d',true)");
    await pool.query("INSERT INTO club_follows (club_id, user_id) VALUES (1, 3), (2, 3)");   // c je Outly izbral sam (samodejno privzeto FALSE)
    const nU = await n("SELECT COUNT(*)::int AS n FROM users"), nObv = await n("SELECT COUNT(*)::int AS n FROM club_event_notifications");
    await pool.query(sql);
    assert((await n("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id = 1")) === nU, `vsi racuni (${nU}) sledijo uradnemu klubu`);
    assert((await n("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id = 1 AND samodejno")) === nU - 1, "dodane vrstice imajo samodejno = TRUE");
    assert((await n("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id = 1 AND user_id = 3 AND NOT samodejno")) === 1, "obstojeca izbrana vrstica (c) ostane samodejno = FALSE");
    assert((await n("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id = 2")) === 1, "navadni klub: samo izbrano sledenje c (ne dodaja)");
    assert((await n("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id IN (3, 4)")) === 0, "skriti in demo uradni klub: nobenih vrstic");
    assert((await n("SELECT COUNT(*)::int AS n FROM club_event_notifications")) === nObv, "migracija ne ustvari obvestil");

    console.log("\n# Ponovni zagon ne naredi nic");
    const pred = (await pool.query("SELECT club_id, user_id, samodejno FROM club_follows ORDER BY 1, 2")).rows;
    await pool.query(sql);
    assert(JSON.stringify((await pool.query("SELECT club_id, user_id, samodejno FROM club_follows ORDER BY 1, 2")).rows) === JSON.stringify(pred), "ponovni zagon 078 ne spremeni nobene vrstice");
  } finally {
    await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  if (fail) process.exit(1);
})().catch((e) => { console.error(e); process.exit(1); });
