#!/usr/bin/env node
/**
 * Test GET /healthz (Render Health Check Path): 200 {ok:true}, ko je baza dosegljiva,
 * in 503 (ne sesutje procesa, ne visenje), ko baza ni dosegljiva. Povezava zdravja, ki obvisi (polodprt TCP: paketi se
 * izgubljajo, povezava se ne zapre), ne sme pustiti /healthz za vedno na 503 - po okrevanju mora spet vrniti 200 (query_timeout).
 * Zagon (lokalno, PG16):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_zdravje.js
 */
const { spawn } = require("child_process");
const net = require("net");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

async function zazeni(port, dbUrl, dodatniEnv = {}) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, REZERVACIJE_CISCENJE_MS: "0", PORT: String(port), DATABASE_URL: dbUrl, SUPABASE_URL: "http://127.0.0.1:1", RESEND_API_KEY: "", QR_SECRET: "test", ...dodatniEnv }, stdio: ["ignore", "pipe", "pipe"] });
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
    assert(r.body && r.body.commit === null, "brez RENDER_GIT_COMMIT je commit null", r.body);
  } finally { a.srv.kill(); }

  console.log("Commit v /healthz (RENDER_GIT_COMMIT):");
  const c = await zazeni(3134, DB, { RENDER_GIT_COMMIT: "0123456789abcdef0123456789abcdef01234567" });
  try {
    const r = await zdravje(3134);
    assert(r.status === 200 && r.body && r.body.ok === true, "GET /healthz -> 200 {ok:true}", r);
    assert(r.body && r.body.commit === "0123456789ab", "commit skrajsan na 12 znakov", r.body);
  } finally { c.srv.kill(); }

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

  console.log("Povezava zdravja obvisi (polodprt TCP), nato se omrezje popravi:");
  // TCP posrednik pred bazo: ob "zamrznitvi" odvrze ves promet v obe smeri, povezave pa ostanejo odprte (kot izgubljeni paketi).
  let zamrznjeno = false;
  const posrednik = net.createServer((odjemalec) => {
    const u = new URL(DB);
    const gor = net.connect(Number(u.port) || 5432, u.hostname);
    odjemalec.on("data", d => { if (!zamrznjeno) gor.write(d); });
    gor.on("data", d => { if (!zamrznjeno) odjemalec.write(d); });
    for (const x of [odjemalec, gor]) { x.on("error", () => {}); x.on("close", () => { odjemalec.destroy(); gor.destroy(); }); }
  });
  await new Promise(r => posrednik.listen(0, "127.0.0.1", r));
  const dbCezPosrednika = (() => { const u = new URL(DB); u.hostname = "localhost"; u.port = String(posrednik.address().port); return u.toString(); })();
  const h = await zazeni(3135, dbCezPosrednika);
  try {
    let r = await zdravje(3135);
    assert(r.status === 200, "pred zamrznitvijo: 200", r);
    zamrznjeno = true;
    r = await zdravje(3135);
    assert(r.status === 503 && r.ms < 5000, "zamrznjena povezava: 503 v < 5 s (ne visi)", r);
    zamrznjeno = false;
    let r2 = null; const t0 = Date.now();
    for (let i = 0; i < 15; i++) { r2 = await zdravje(3135); if (r2.status === 200) break; await new Promise(x => setTimeout(x, 500)); }
    assert(r2 && r2.status === 200, "po okrevanju omrezja /healthz spet 200 (obvisela povezava je unicena, ne ostane za vedno 503)", r2);
    console.log(`    (okrevanje po ${Date.now() - t0} ms)`);
  } finally { h.srv.kill(); posrednik.close(); }

  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
