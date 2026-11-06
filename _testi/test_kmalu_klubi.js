#!/usr/bin/env node
/**
 * Klubi »Coming soon« (Martin 6. 11. 2026): javni GET /coming-soon vrne seznam iz podatki/kmalu_klubi.json.
 * Pot ne kliče JWKS in baze: neveljaven Authorization ne sme dati 401/503. Datoteka s podatki se tu strogo preveri
 * (neveljavna datoteka pade TA test, proces v produkciji pa je ne sme sesuti: modul vrne prazen seznam).
 * Zagon: DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_kmalu_klubi.js
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6440;
let ok = 0, fail = 0;
function assert(c, m, e) { if (c) { ok++; console.log("  ✓", m); } else { fail++; console.log("  ✗", m, e !== undefined ? JSON.stringify(e) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));
const get = (p, headers) => new Promise((res, rej) => {
  http.get({ host: "127.0.0.1", port: PORT, path: p, headers }, (x) => {
    let b = ""; x.on("data", (d) => b += d);
    x.on("end", () => { let j = null; try { j = JSON.parse(b); } catch (_) {} res({ status: x.statusCode, h: x.headers, body: b, json: j }); });
  }).on("error", rej);
});

const POLJA = ["slug", "name", "city", "address", "logo_url", "cover_url", "website", "instagram"];
const SLUGI = ["square", "cirkus", "k4", "shooters", "cutty-sark"];

(async () => {
  console.log("\n# datoteka podatki/kmalu_klubi.json (validacija)");
  const modul = require("../kmalu_klubi");
  const surovo = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "podatki", "kmalu_klubi.json"), "utf8"));
  const napake = modul.validiraj(surovo);
  assert(napake.length === 0, "prava datoteka je veljavna", napake);
  const dobro = surovo.clubs[0];
  const z = (s) => modul.validiraj({ clubs: [dobro, s] }).length > 0;
  assert(modul.validiraj({}).length > 0 && modul.validiraj(null).length > 0 && modul.validiraj({ clubs: "x" }).length > 0, "brez clubs[] -> napaka");
  assert(z({ ...dobro }), "podvojen slug -> napaka");
  assert(z({ ...dobro, slug: "Veliki" }) && z({ ...dobro, slug: "a b" }) && z({ ...dobro, slug: "" }), "slug zunaj ^[a-z0-9-]+$ -> napaka");
  assert(z({ ...dobro, slug: "x", name: "" }) && z({ ...dobro, slug: "x", name: "  " }), "prazen name -> napaka");
  assert(z({ ...dobro, slug: "x", logo_url: "http://a.si/x.png" }) && z({ ...dobro, slug: "x", cover_url: "javascript:alert(1)" }) && z({ ...dobro, slug: "x", website: "//a.si" }), "URL ni https -> napaka");
  assert(!z({ ...dobro, slug: "x", logo_url: "", cover_url: "", website: "", instagram: "", address: "" }), "prazni URL-ji in polja so dovoljeni");
  assert(z({ ...dobro, slug: "x", instagram: "@klub" }) && z({ ...dobro, slug: "x", instagram: "https://instagram.com/klub" }) && z({ ...dobro, slug: "x", instagram: "a/b" }), "instagram z @ ali / -> napaka");
  assert(z({ ...dobro, slug: "x", city: null }) && z({ ...dobro, slug: "x", address: 5 }), "polje ni niz -> napaka");
  assert(z({ ...dobro, slug: "x", dodatno: "a" }), "neznano polje -> napaka");

  console.log("\n# GET /coming-soon");
  const srv = spawn("node", ["index.js"], { env: { ...process.env, REZERVACIJE_CISCENJE_MS: "0", DNEVNIK_POVEZAV_MS: "0", PORT: String(PORT), DATABASE_URL: DB, SUPABASE_URL: "http://127.0.0.1:1", RESEND_API_KEY: "" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 200 && !log.includes("Server running on port"); i++) await spi(50);
  try {
    const r = await get("/coming-soon");
    assert(r.status === 200, "brez glave -> 200", [r.status, r.body.slice(0, 200)]);
    assert(r.json && Array.isArray(r.json.clubs) && Object.keys(r.json).length === 1, "oblika { clubs: [...] }", r.json && Object.keys(r.json));
    const k = (r.json && r.json.clubs) || [];
    assert(k.length === 5, "natanko 5 klubov", k.length);
    assert(JSON.stringify(k.map((c) => c.slug)) === JSON.stringify(SLUGI), "vrstni red square, cirkus, k4, shooters, cutty-sark", k.map((c) => c.slug));
    assert(k.every((c) => JSON.stringify(Object.keys(c)) === JSON.stringify(POLJA)), "vseh 8 polj v dogovorjenem vrstnem redu", k.map((c) => Object.keys(c)));
    assert(k.every((c) => POLJA.every((p) => typeof c[p] === "string")), "vsa polja so nizi (nikoli null)");
    const sq = k[0] || {};
    assert(sq.name === "Square Club" && sq.address === "Kongresni trg 3, 1000 Ljubljana" && sq.instagram === "square_ljubljana" && sq.website === "https://squareclub.si/", "Square: podatki po pogodbi", sq);
    const sh = k[3] || {};
    assert(sh.slug === "shooters" && sh.address === "Nazorjeva ulica 6a, 1000 Ljubljana" && sh.website === "" && sh.instagram === "", "Shooters: naslov potrjen (Martin 6. 11.), splet in instagram prazna", sh);
    assert(r.h["cache-control"] === "public, max-age=300", "Cache-Control: public, max-age=300", r.h["cache-control"]);
    assert((r.h["content-type"] || "").startsWith("application/json"), "application/json", r.h["content-type"]);

    const n = await get("/coming-soon", { Authorization: "Bearer xxx" });
    assert(n.status === 200 && n.body === r.body, "neveljaven Bearer -> 200 (ne 401, ne 503), isti odgovor", [n.status]);
    const d = await get("/coming-soon?x=1");
    assert(d.status === 200 && d.body === r.body, "poizvedbeni niz ne spremeni odgovora", d.status);
  } finally { srv.kill(); }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error("NEPRICAKOVANO:", e); process.exit(1); });
