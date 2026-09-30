#!/usr/bin/env node
/**
 * Test GET /healthz (Render Health Check Path): 200 {ok:true}, ko je baza dosegljiva,
 * in 503 (ne sesutje procesa, ne visenje), ko baza ni dosegljiva.
 * Zagon (lokalno, PG16):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_zdravje.js
 */
const { spawn } = require("child_process");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

async function zazeni(port, dbUrl) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), DATABASE_URL: dbUrl, SUPABASE_URL: "http://127.0.0.1:1", RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(`http://127.0.0.1:${port}/`); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
  return { srv, log: () => log };
}
async function zdravje(port) {
  const t0 = Date.now();
  const r = await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(15000) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, ms: Date.now() - t0, cache: r.headers.get("cache-control") };
}

(async () => {
  console.log("Baza dosegljiva:");
  const a = await zazeni(3131, DB);
  try {
    const r = await zdravje(3131);
    assert(r.status === 200, "GET /healthz -> 200", r);
    assert(r.body && r.body.ok === true, "telo {ok:true}", r.body);
    assert(r.cache === "no-store", "Cache-Control: no-store", r.cache);
  } finally { a.srv.kill(); }

  console.log("Baza NI dosegljiva:");
  const b = await zazeni(3132, "postgres://postgres:postgres@localhost:1/outly");
  try {
    const r = await zdravje(3132);
    assert(r.status === 503, "GET /healthz -> 503", r);
    assert(r.body && r.body.ok === false, "telo {ok:false}", r.body);
    assert(r.ms < 5000, "odgovor v < 5 s (ne visi)", r.ms);
    const r2 = await fetch("http://127.0.0.1:3132/").then(x => x.status).catch(() => 0);
    assert(r2 === 200, "proces po napaki baze se tece", r2);
  } finally { b.srv.kill(); }

  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
