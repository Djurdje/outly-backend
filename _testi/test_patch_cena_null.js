#!/usr/bin/env node
/**
 * Test: PATCH /events/:id sme nastaviti ticket_price_cents na NULL (dogodek brez vstopnic na Outlyju). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_patch_cena_null.js
 * Vzorec kot test_nakup_cena.js: lokalni JWKS (5794), backend na svojem portu (5793), TRUNCATE na zacetku.
 *
 * Pred popravkom je `b.ticketPriceCents ?? b.ticket_price_cents` iz izrecnega null naredil undefined: `{ ticketPriceCents: null }` je vrnil
 * 400 »Nothing to update.« in prodaje ni bilo mogoce ustaviti (21. 10. 2026, dogodek 35). POST /events null ze dovoli.
 *  1  lastnik kluba: PATCH { ticketPriceCents: null } -> 200, cena null (odgovor in baza); nakup -> 409 »This event has no tickets on Outly.«
 *  2  PATCH brez kljuca cene ne spremeni cene (null ostane null); PATCH { ticketPriceCents: 1000 } -> 1000, nakup spet 201
 *  3  admin: isto, tudi s snake_case kljucem { ticket_price_cents: null }; nato 1000 in nakup 201; PATCH brez kljuca ne spremeni 1000
 *  4  kontrola: neveljavne vrednosti (-1, 10.5, "abc") ostanejo 400, cena se ne spremeni; prazno telo ostane 400 »Nothing to update.«
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 5793, JWKS_PORT = 5794;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-patch-cena-null";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
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
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

let srv = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", TEST_PLACILA: "" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), admin: zeton("admin@outly.si", uuid(2)), ana: zeton("ana@outly.si", uuid(3)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");

    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (title) => {
      const x = await api("POST", "/events", T.lastnik, { clubId: 1, title, startAt: cezDan, ticketPriceCents: 1000, capacity: 500, minAge: 0 });
      assert(x.status === 201 && x.body.ticket_price_cents === 1000, `dogodek ${title} (1000 c)`, x.body); return x.body.id;
    };
    const cenaVBazi = async (ev) => (await pool.query("SELECT ticket_price_cents FROM events WHERE id=$1", [ev])).rows[0].ticket_price_cents;
    const kupi = (ev) => api("POST", `/events/${ev}/orders`, T.ana, { quantity: 1 });
    const BREZ = "This event has no tickets on Outly.";

    for (const [vloga, kljuc] of [["lastnik", "ticketPriceCents"], ["admin", "ticketPriceCents"], ["admin", "ticket_price_cents"]]) {
      await pool.query("TRUNCATE omejitve");
      console.log(`\n# ${vloga}, kljuc ${kljuc}`);
      const ev = await dogodek(`${vloga} ${kljuc}`);
      let r = await kupi(ev);
      assert(r.status === 201, "pred ustavitvijo nakup 201", r.body);

      r = await api("PATCH", `/events/${ev}`, T[vloga], { [kljuc]: null });
      assert(r.status === 200 && r.body.ticket_price_cents === null, `PATCH { ${kljuc}: null } -> 200, cena null`, { status: r.status, body: r.body });
      assert(await cenaVBazi(ev) === null, "v bazi NULL", await cenaVBazi(ev));
      r = await kupi(ev);
      assert(r.status === 409 && r.body === BREZ, `nakup -> 409 »${BREZ}«`, { status: r.status, body: r.body });

      r = await api("PATCH", `/events/${ev}`, T[vloga], { title: `${vloga} preimenovan` });
      assert(r.status === 200 && r.body.ticket_price_cents === null && await cenaVBazi(ev) === null, "PATCH brez kljuca cene: null ostane null", { status: r.status, body: r.body });

      r = await api("PATCH", `/events/${ev}`, T[vloga], { [kljuc]: 1000 });
      assert(r.status === 200 && r.body.ticket_price_cents === 1000 && await cenaVBazi(ev) === 1000, `PATCH { ${kljuc}: 1000 } -> cena 1000`, { status: r.status, body: r.body });
      r = await kupi(ev);
      assert(r.status === 201 && r.body.order && r.body.order.total_cents === 1000, "nakup spet 201 po 1000", { status: r.status, body: r.body });

      r = await api("PATCH", `/events/${ev}`, T[vloga], { capacity: 400 });
      assert(r.status === 200 && r.body.ticket_price_cents === 1000 && await cenaVBazi(ev) === 1000, "PATCH brez kljuca cene: 1000 ostane 1000", { status: r.status, body: r.body });
    }

    console.log("\n# Kontrola: neveljavne vrednosti in prazno telo");
    const evK = await dogodek("Kontrola");
    for (const slab of [-1, 10.5, "abc"]) {
      const r = await api("PATCH", `/events/${evK}`, T.lastnik, { ticketPriceCents: slab });
      assert(r.status === 400 && /ticketPriceCents must be a non-negative integer/.test(r.body), `ticketPriceCents ${JSON.stringify(slab)} -> 400`, { status: r.status, body: r.body });
    }
    assert(await cenaVBazi(evK) === 1000, "cena po 400 nespremenjena (1000)");
    const r = await api("PATCH", `/events/${evK}`, T.lastnik, {});
    assert(r.status === 400 && r.body === "Nothing to update.", "prazno telo -> 400 »Nothing to update.« kot doslej", { status: r.status, body: r.body });
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    srv.kill(); jwksServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + log.split("\n").slice(-40).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
