#!/usr/bin/env node
/**
 * Test casovnih mej povezav (issue #139, korak 2): keepAliveTimeout (KEEPALIVE_MS, privzeto 120000) in headersTimeout = keepAlive + 1 s.
 * Zagon (lokalno, PG16, baza z vsemi migracijami; baza je potrebna samo, da proces zazene):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_keepalive.js
 * (a) enotsko: vrednosti, meje, neveljaven vnos; (b) proces na portu 3182 (privzeto): vzdrzevana povezava preziv 6,5 s mirovanja
 * (Node brez popravka jo zapre po 5 s); (c) proces na portu 3183 z KEEPALIVE_MS=1000: povezavo zapre sam (kontrola, da je nastavitev
 * res povezana). Cas: ~8 s.
 */
const http = require("http");
const { spawn } = require("child_process");
const { nastaviMejePovezav, keepAliveIzOkolja, PRIVZETO_MS, NAJVEC_MS } = require("../nastavitve_povezav");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3182, PORT_B = 3183;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

function enotski() {
  console.log("\n# Enotski testi: vrednosti in meje");
  const tiho = { opozori: () => {} };
  const dobi = (surovo) => { const s = http.createServer(); const m = nastaviMejePovezav(s, surovo, tiho); return { s, m }; };
  let { s, m } = dobi(undefined);
  assert(s.keepAliveTimeout === 120000 && s.headersTimeout === 121000 && PRIVZETO_MS === 120000, "privzeto: keepAlive 120000, headersTimeout 121000", [s.keepAliveTimeout, s.headersTimeout]);
  assert(m.keepAliveMs === 120000 && m.headersMs === 121000, "vrnjene vrednosti ustrezajo nastavljenim", m);
  assert(s.requestTimeout >= s.headersTimeout, "requestTimeout ostane >= headersTimeout (300 s)", [s.requestTimeout, s.headersTimeout]);
  ({ s } = dobi("3000"));
  assert(s.keepAliveTimeout === 3000 && s.headersTimeout === 4000, "KEEPALIVE_MS=3000 -> 3000 / 4000", [s.keepAliveTimeout, s.headersTimeout]);
  for (const slabo of ["", "0", "-5", "abc", "NaN", "Infinity", "0.5"]) {
    ({ s } = dobi(slabo));
    assert(s.keepAliveTimeout === 120000 && s.headersTimeout === 121000, `KEEPALIVE_MS='${slabo}' -> privzeto (0 bi izklopil rok v Node)`, s.keepAliveTimeout);
  }
  ({ s } = dobi("99999999"));
  assert(s.keepAliveTimeout === NAJVEC_MS && s.headersTimeout === NAJVEC_MS + 1000 && s.headersTimeout < s.requestTimeout, "zgornja meja 280000; headersTimeout se vedno < requestTimeout", [s.keepAliveTimeout, s.headersTimeout, s.requestTimeout]);
  for (const v of [1, 1000, 5000, 120000, 280000]) {
    ({ s } = dobi(String(v)));
    assert(s.headersTimeout > s.keepAliveTimeout, `headersTimeout > keepAliveTimeout pri ${v}`);
  }
  let opozorilo = null;
  keepAliveIzOkolja("abc", { opozori: (x) => { opozorilo = x; } });
  assert(/KEEPALIVE_MS="abc"/.test(opozorilo || ""), "neveljavna vrednost se izpise (brez poverilnic)", opozorilo);
}

function zazeni(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, REZERVACIJE_CISCENJE_MS: "0", DNEVNIK_POVEZAV_MS: "0", PORT: String(port), DATABASE_URL: DB, SUPABASE_URL: "http://127.0.0.1:1", RESEND_API_KEY: "", QR_SECRET: "test", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const st = { srv, log: "" };
  srv.stdout.on("data", (d) => st.log += d); srv.stderr.on("data", (d) => st.log += d);
  return st;
}
async function pripravljen(st) { for (let i = 0; i < 200; i++) { if (st.log.includes("Server running on port")) return true; await spi(50); } return false; }

// En zahtevek prek agenta z vzdrzevanjem; vrne { status, ponovno } (ponovno = uporabljena je ista TCP povezava kot prej).
function get(agent, port) {
  return new Promise((res, rej) => {
    const r = http.get({ host: "127.0.0.1", port, path: "/", agent }, (x) => { x.resume(); x.on("end", () => res({ status: x.statusCode, ponovno: r.reusedSocket })); });
    r.on("error", rej);
  });
}

(async () => {
  enotski();
  const A = zazeni(PORT_A, {}), B = zazeni(PORT_B, { KEEPALIVE_MS: "1000" });
  const agA = new http.Agent({ keepAlive: true, maxSockets: 1 }), agB = new http.Agent({ keepAlive: true, maxSockets: 1 });
  try {
    assert(await pripravljen(A) && await pripravljen(B), "oba procesa sta se zagnala");
    console.log("\n# Proces: vrednosti v dnevniku");
    assert(/\[meje-povezav\] keepAliveTimeout 120000 ms, headersTimeout 121000 ms, requestTimeout 300000 ms/.test(A.log), "A: zagonski dnevnik kaze 120000 / 121000", A.log.slice(0, 300));
    assert(/\[meje-povezav\] keepAliveTimeout 1000 ms, headersTimeout 2000 ms/.test(B.log), "B: KEEPALIVE_MS=1000 -> 1000 / 2000");

    console.log("\n# Vzdrzevana povezava preziv mirovanje dalj od Nodovih 5 s (A)");
    let r = await get(agA, PORT_A);
    assert(r.status === 200 && r.ponovno === false, "A: prvi zahtevek na novi povezavi", r);
    await get(agB, PORT_B);
    await spi(6500);
    r = await get(agA, PORT_A);
    assert(r.status === 200 && r.ponovno === true, "A: po 6,5 s mirovanja je ISTA povezava se odprta (Node brez popravka bi jo zaprl po 5 s)", r);
    r = await get(agB, PORT_B);
    assert(r.status === 200 && r.ponovno === false, "B (KEEPALIVE_MS=1000): po 6,5 s je povezavo zaprl strežnik -> nova povezava (kontrola, da je nastavitev povezana)", r);
    assert(!/Unhandled|TypeError|ReferenceError/.test(A.log + B.log), "dnevnik brez neujetih napak");
  } finally {
    agA.destroy(); agB.destroy();
    A.srv.kill(); B.srv.kill();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
