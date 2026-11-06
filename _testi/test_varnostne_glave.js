#!/usr/bin/env node
/**
 * Varnostne glave (varnostni pregled 6. 11. 2026): admin panel (/admin/) dobi X-Frame-Options, frame-ancestors, nosniff, Referrer-Policy;
 * nobena ppot ne pokaze X-Powered-By; API ima nosniff. Polne script-src CSP namenoma ni (panel nalaga Supabase).
 * Zagon: DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_varnostne_glave.js
 */
const http = require("http");
const { spawn } = require("child_process");
const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3191;
let ok = 0, fail = 0;
function assert(c, m, e) { if (c) { ok++; console.log("  ✓", m); } else { fail++; console.log("  ✗", m, e !== undefined ? JSON.stringify(e) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));
const get = (p) => new Promise((res, rej) => { http.get({ host: "127.0.0.1", port: PORT, path: p }, (x) => { x.resume(); x.on("end", () => res({ status: x.statusCode, h: x.headers })); }).on("error", rej); });

(async () => {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, REZERVACIJE_CISCENJE_MS: "0", DNEVNIK_POVEZAV_MS: "0", PORT: String(PORT), DATABASE_URL: DB, SUPABASE_URL: "http://127.0.0.1:1", RESEND_API_KEY: "" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 200 && !log.includes("Server running on port"); i++) await spi(50);
  try {
    console.log("\n# /admin/ (staticni panel)");
    const a = await get("/admin/");
    assert(a.status === 200, "GET /admin/ -> 200", a.status);
    assert(a.h["x-frame-options"] === "DENY", "X-Frame-Options: DENY", a.h["x-frame-options"]);
    assert(a.h["content-security-policy"] === "frame-ancestors 'none'", "CSP: samo frame-ancestors 'none' (brez script-src)", a.h["content-security-policy"]);
    assert(a.h["x-content-type-options"] === "nosniff", "nosniff", a.h["x-content-type-options"]);
    assert(a.h["referrer-policy"] === "same-origin", "Referrer-Policy: same-origin", a.h["referrer-policy"]);
    assert(a.h["x-powered-by"] === undefined, "brez X-Powered-By", a.h["x-powered-by"]);
    const ostalo = await get("/admin/ni-te-datoteke.js");
    assert(ostalo.h["x-frame-options"] === "DENY", "glave tudi na drugih odgovorih pod /admin (404)", ostalo.h["x-frame-options"]);
    console.log("\n# API");
    const c = await get("/clubs");
    assert(c.status === 200, "GET /clubs -> 200", c.status);
    assert(c.h["x-powered-by"] === undefined, "/clubs brez X-Powered-By", c.h["x-powered-by"]);
    assert(c.h["x-content-type-options"] === "nosniff", "/clubs ima nosniff", c.h["x-content-type-options"]);
    const n = await get("/ni-poti");
    assert(n.h["x-powered-by"] === undefined && n.h["x-content-type-options"] === "nosniff", "404 tudi brez X-Powered-By in z nosniff", n.h);
    const m = await get("/me/invites");
    assert(m.status === 401 && m.h["x-powered-by"] === undefined, "401 brez X-Powered-By", [m.status, m.h["x-powered-by"]]);
  } finally { srv.kill(); }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
