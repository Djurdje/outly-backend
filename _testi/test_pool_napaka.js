#!/usr/bin/env node
/**
 * Test: baza prekine MIRUJOCE povezave v poolu (vzdrzevanje / ponovni zagon baze na Renderju, izpad omrezja).
 * node-postgres odda 'error' na poolu; brez poslusalca je to "Unhandled 'error' event" in CEL backend pade
 * (tudi skeniranje na vratih, nakupi). Pricakovano: proces zivi, GET /clubs in /events -> 200 (pool odpre nove povezave).
 * Zagon (lokalno, PG16):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_pool_napaka.js
 * Seje backenda najdemo po application_name (dodan v DATABASE_URL), zato testna povezava in druge seje ostanejo pri miru.
 */
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3133;
const BASE = `http://127.0.0.1:${PORT}`;
const IME = "outly_test_pool_napaka";
const dbZImenom = DB + (DB.includes("?") ? "&" : "?") + "application_name=" + IME;

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const admin = new Pool({ connectionString: DB, ssl: DB.includes("localhost") ? false : { rejectUnauthorized: false }, max: 1 });
  admin.on("error", () => {});
  const seje = async () => (await admin.query(
    "SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND pid <> pg_backend_pid()", [IME])).rows.map((r) => r.pid);

  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), DATABASE_URL: dbZImenom, SUPABASE_URL: "http://127.0.0.1:1", RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  let umrl = null; srv.on("exit", (code, sig) => { umrl = { code, sig }; });

  try {
    for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await spi(100); } }

    console.log("Pool z mirujocimi povezavami:");
    // vzporedni zahtevki -> pool odpre vec povezav, nato mirujejo (idleTimeoutMillis pg poola je 10 s)
    const odzivi = await Promise.all(Array.from({ length: 8 }, (_, i) => fetch(BASE + (i % 2 ? "/events" : "/clubs")).then((r) => r.status)));
    assert(odzivi.every((s) => s === 200), "8 vzporednih GET /clubs|/events -> 200", odzivi);
    await spi(300);
    const pred = await seje();
    assert(pred.length >= 2, "backend ima vec mirujocih povezav v poolu", pred.length);

    console.log("Baza prekine vse seje backenda (pg_terminate_backend):");
    for (const pid of pred) await admin.query("SELECT pg_terminate_backend($1)", [pid]);
    await spi(1500); // pg odda 'error' na vsaki mirujoci povezavi

    assert(umrl === null, "proces backenda se zivi", { umrl, log: log.slice(-600) });
    assert(!/Unhandled 'error'/.test(log), "brez \"Unhandled 'error' event\" v dnevniku");
    const c = await fetch(BASE + "/clubs").then((r) => r.status).catch(() => 0);
    const e = await fetch(BASE + "/events").then((r) => r.status).catch(() => 0);
    assert(c === 200, "GET /clubs -> 200 (pool je odprl novo povezavo)", c);
    assert(e === 200, "GET /events -> 200", e);
    const po = await seje();
    assert(po.length >= 1 && po.every((p) => !pred.includes(p)), "nove povezave z drugimi pid-i", { pred, po });
    assert(/\[pool\]/.test(log), "napaka povezave je zapisana v dnevnik (ni tiha)", log.slice(-300));
  } finally {
    srv.kill();
    await admin.end().catch(() => {});
  }

  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
