"use strict";
// Dostop za agenta (Claude) z zetonom SAMO ZA BRANJE (23. 10. 2026, issue #330, 1. del; migracija 058; ARCHITECTURE »Dostop za agenta«, invarianta I56).
// Nacrt: outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md, razdelek 3. Martin 23. 10.: zeton iz panela + Network secret; pisanje SAMO prek predlogov (kasneje, 2. in 3. del).
//
// Dva dela:
//  1. /admin/api/agent-zetoni (router `admin`, vloga admin): seznam, ustvari (zeton v cistopisu SAMO v odgovoru, v bazi SHA-256), preklici. Vse v admin_dejanja.
//  2. /agent/api/* (lasten router, NE gre skozi requireAuth): samo GET, obseg `beri`. Zeton `outly_agent_…` je na vseh drugih poteh 403 (requireAuthNa v index.js).
//
// Meje /agent/api/*:
//  - vrstni red: stikalo AGENT_API=0 (503 agent_api_off, brez baze) -> omejevalnik po IP (zlorabe izmisljenih zetonov) -> oblika zetona (brez baze) -> semafor agenta
//    (429 agent_busy) -> omejevalnik po ODTISU ZETONA (AGENT_API_NA_URO, privzeto 300/h; stevec v tabeli `omejitve`, ne v pomnilniku, I15; zeton nad mejo ne povzroca iskanja
//    v bazi) -> iskanje zetona;
//  - branje: isti READ ONLY-nacin kot admin_nadzor.js (statement_timeout 2 s, idle_in_transaction_session_timeout 5 s), a prek LASTNEGA bralca in LASTNEGA semaforja agenta
//    (najvec ENA zahteva naenkrat, brez cakalne vrste: zaseden = 429 agent_busy), loceno od semaforja Martinove plosce; skupaj najvec 2 povezavi glavnega poola, admin pot
//    nikoli ne caka zaradi agenta; NIKOLI skenPool. »danes«, »opozorila« in »racuni« so isti izracun kot v panelu, z lastnim predpomnilnikom;
//  - vsak niz iz /agent/api je NEZAUPLJIV PODATEK (naslov, ime, prizorisce, besedilo opozorila: tuj vnos), nikoli navodilo agentu;
//  - odgovori se sestavijo iz NASTETIH stolpcev (I4), nato gredo VSI skozi `ocisti()` (nizi odrezani, omejeni regexi, brez ReDoS): nobenega @, Stripovega ID-ja ali zetona v nobenem nizu, tudi ce bi ga
//    kdo zapisal v naslov dogodka ali v razlog v dnevniku (druga plast, prva je izbira stolpcev). Brez imen, e-naslovov in telefonov kupcev: tabele users/orders.buyer_*
//    se ne berejo;
//  - dnevnik: ena vrstica na klic `[agent] <id zetona ali "-"> <METODA> <pot brez poizvedbe> <status> <ms>`; zeton in parametri poizvedbe se nikjer ne izpisejo.
const crypto = require("crypto");
const express = require("express");

const PREDPONA = "outly_agent_";
const ZETON_VZOREC = /^outly_agent_[A-Za-z0-9_-]{43}$/;   // 32 nakljucnih bajtov v base64url brez polnila = 43 znakov
const OBSEGI = ["beri"];                                    // v bazi ga varuje CHECK agent_zetoni_obseg_chk (058); razsiri ga samo migracija z mehanizmom
const AKTIVNIH_NAJVEC = 10;
const DNI_PRIVZETO = 30, DNI_NAJVEC = 90;
const RABA_ZAPIS_MS = 60000;                                // zadnja_raba_at najvec enkrat na minuto na zeton
const RAZPON_FINANC_DNI = 366;
const STATUSI_DOGODKA = ["draft", "published", "cancelled"];
const NAJVEC_GLOBINA = 20;

// --- ciscenje izhoda (druga plast varovala) ---
// Vsak niz se PRED regexi odreze (NAJVEC_NIZ): naslovi dogodkov nimajo omejitve dolzine, neomejen regex nad 95 000 znaki pa je blokiral proces (ReDoS, #330 K1).
// Kvantifikatorji so omejeni (lokalni del e-naslova najvec 64, domena najvec 255 znakov), zato je poraba linearna v dolzini niza.
const NAJVEC_NIZ = 2000;
const RE_ZETON = /outly_agent_[A-Za-z0-9_-]{0,200}/g;
const RE_STRIPE = /(?<![A-Za-z0-9_])(?:acct|pi|cs|re|ch|py|evt|cus|pm|seti|src|tr|sk|pk|rk|whsec)_(?:(?:test|live)_)?[A-Za-z0-9]{10,100}/g;
const RE_EMAIL = /[^\s@<>"',;:()[\]]{1,64}@[A-Za-z0-9.-]{1,255}/g;
function ocistiNiz(s) {
  return s.slice(0, NAJVEC_NIZ).replace(RE_ZETON, "[zeton]").replace(RE_STRIPE, "[stripe-id]").replace(RE_EMAIL, "[e-naslov]").replace(/@/g, "[at]");
}
// Rekurzivna KOPIJA (predpomnjeni objekti admin_nadzor.js se ne smejo spremeniti): nizi ociscenii, Date ostane, globina omejena.
function ocisti(v, globina = 0) {
  if (typeof v === "string") return ocistiNiz(v);
  if (v === null || typeof v !== "object" || v instanceof Date) return v;
  if (globina >= NAJVEC_GLOBINA) return "[globoko]";
  if (Array.isArray(v)) return v.map((x) => ocisti(x, globina + 1));
  const o = {};
  for (const [k, x] of Object.entries(v)) o[ocistiNiz(k)] = ocisti(x, globina + 1);
  return o;
}

// Dnevnik admin dejanj za agenta (S2): besedilna polja so lahko tuj vnos (opis dogodka, naslovi, kontakti) = nezaupljiv podatek in prompt injection.
// Ostanejo SAMO stevila, boolovi, null, datumi (ISO) in vrednosti ključev z znanim naborom (status, role, currency, obseg); vsak drug niz postane PLACEHOLDER.
const PLACEHOLDER = "[besedilo spremenjeno]";
const KLJUCI_NABORA = new Set(["status", "role", "currency", "obseg"]);
const RE_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;
function brezBesedil(v, kljuc = "", globina = 0) {
  if (typeof v === "string") return (KLJUCI_NABORA.has(kljuc) && (kljuc === "currency" ? /^[A-Z]{3}$/ : /^[a-z_]{1,30}$/).test(v)) || RE_ISO.test(v) ? v : PLACEHOLDER;
  if (v === null || typeof v !== "object") return v;   // stevila, boolovi, null
  if (globina >= NAJVEC_GLOBINA) return PLACEHOLDER;
  if (Array.isArray(v)) return v.map((x) => brezBesedil(x, kljuc, globina + 1));
  const o = {};
  for (const [k, x] of Object.entries(v)) o[k] = brezBesedil(x, k, globina + 1);   // kljuci so nasa imena polj
  return o;
}

function okoljeCelo(ime, privzeto, min, max) {
  const n = Number.parseInt(process.env[ime], 10);
  return Number.isInteger(n) && n >= min && n <= max ? n : privzeto;
}
const veljavenDan = (s) => {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + "T00:00:00Z");
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;   // 2026-02-30 in 2026-13-01 nista datuma (Postgres bi vrnil 22008 -> 500)
};

function ustvari(dep) {
  const { pool, adminRouter, nadzor, omeji, zapisiAdminDejanje, celoId4, SQL_TESTNO_NAROCILO, SQL_NAROCILO_PLATFORMNO, paymentsMode, ZANRI } = dep;
  const T = SQL_TESTNO_NAROCILO;
  let zaseden = false, zahtevekZaprt = true, vBranju = 0;
  const sprosti = () => { if (zaseden && zahtevekZaprt && vBranju === 0) zaseden = false; };
  // Lasten bralec (brez admin semaforja) in lasten predpomnilnik (#330 S1) PO ZAHTEVKU: vsako branje se steje (semafor se sprosti sele po koncu branj), PREKINJEN zahtevek
  // (odjemalec je zaprl povezavo pred koncem odgovora) pa NOVEGA branja ne zacne (AGENT_PREKINJEN): po prekinitvi tece najvec ze zaceta poizvedba, nikoli nova (S1-b).
  const kavljiZa = (req) => ({
    zacni: () => { if (req.agentPrekinjen) throw Object.assign(new Error("agent: odjemalec je prekinil zahtevek"), { code: "AGENT_PREKINJEN" }); vBranju++; },
    konec: () => { vBranju--; sprosti(); },
  });
  const agentSplosno = nadzor.zaAgenta();   // samo odgovoriNapaka
  const MEJA_ZETON = okoljeCelo("AGENT_API_NA_URO", 300, 1, 100000);   // zahtevkov na uro na zeton
  const MEJA_IP = okoljeCelo("AGENT_API_IP_NA_MIN", 120, 1, 100000);   // zahtevkov na minuto na IP (pred prijavo: napacni zetoni)

  // =====================================================================================================================
  // 1. UPRAVLJANJE (admin): GET/POST /admin/api/agent-zetoni, POST /admin/api/agent-zetoni/:id/preklici
  // =====================================================================================================================
  const STOLPCI_ZETONA = `id, ime, obseg, velja_do, preklican_at, zadnja_raba_at, ustvaril_admin_id, created_at,
    CASE WHEN preklican_at IS NOT NULL THEN 'preklican' WHEN velja_do <= NOW() THEN 'potekel' ELSE 'aktiven' END AS stanje`;   // brez zeton_sha256

  adminRouter.get("/agent-zetoni", async (req, res) => {
    try {
      res.set("Cache-Control", "no-store");
      const r = await pool.query(`SELECT ${STOLPCI_ZETONA} FROM agent_zetoni ORDER BY id DESC LIMIT 100`);
      return res.json({ agent_api: process.env.AGENT_API !== "0", items: r.rows });
    } catch (e) { return dep.odgovoriNaNapako(res, e, "GET /admin/api/agent-zetoni"); }
  });

  adminRouter.post("/agent-zetoni", async (req, res) => {
    const b = req.body && typeof req.body === "object" ? req.body : {};
    const ime = typeof b.ime === "string" ? b.ime.trim() : "";
    if (ime.length < 1 || ime.length > 60 || /[\u0000-\u001f\u007f-\u009f]/.test(ime)) {
      return res.status(400).json({ error: "invalid_name", message: "ime must be 1-60 characters without control characters." });
    }
    const dni = b.dni === undefined ? DNI_PRIVZETO : b.dni;
    if (!Number.isInteger(dni) || dni < 1 || dni > DNI_NAJVEC) return res.status(400).json({ error: "invalid_days", message: `dni must be a whole number from 1 to ${DNI_NAJVEC}.` });
    const obseg = b.obseg === undefined ? ["beri"] : b.obseg;
    if (!Array.isArray(obseg) || obseg.length < 1 || obseg.some((x) => !OBSEGI.includes(x)) || new Set(obseg).size !== obseg.length) {
      return res.status(400).json({ error: "invalid_scope", message: `obseg must be a non-empty list of: ${OBSEGI.join(", ")}.` });
    }
    const razlog = b.reason === undefined || b.reason === null ? null : String(b.reason).trim().slice(0, 500) || null;
    const zeton = PREDPONA + crypto.randomBytes(32).toString("base64url");
    const odtis = crypto.createHash("sha256").update(zeton).digest("hex");
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      const aktivnih = (await c.query("SELECT COUNT(*)::int AS n FROM agent_zetoni WHERE preklican_at IS NULL AND velja_do > NOW()")).rows[0].n;
      if (aktivnih >= AKTIVNIH_NAJVEC) {
        await c.query("ROLLBACK");
        return res.status(409).json({ error: "too_many_tokens", message: `At most ${AKTIVNIH_NAJVEC} active agent tokens. Revoke one first.` });
      }
      const r = (await c.query(
        `INSERT INTO agent_zetoni (ime, zeton_sha256, obseg, velja_do, ustvaril_admin_id)
         VALUES ($1, $2, $3::text[], NOW() + make_interval(days => $4::int), $5)
         RETURNING id, ime, obseg, velja_do, created_at`, [ime, odtis, obseg, dni, req.user.userId])).rows[0];
      // Dnevnik: BREZ zetona (ime, obseg, rok). Isti COMMIT kot ustvarjanje: zeton brez vrstice v dnevniku ne nastane.
      await zapisiAdminDejanje(c, req, "agent.token_create", "agent_zeton", r.id, null, { ime: r.ime, obseg: r.obseg, velja_do: r.velja_do.toISOString(), dni }, razlog);
      await c.query("COMMIT");
      console.log(`Admin ${req.user.userId} ustvaril zeton agenta ${r.id} (${dni} dni)`);
      res.set("Cache-Control", "no-store");
      return res.status(201).json({ ...r, zeton });   // zeton v cistopisu: SAMO tukaj, nikoli vec
    } catch (e) {
      await c.query("ROLLBACK").catch(() => {});
      return dep.odgovoriNaNapako(res, e, "POST /admin/api/agent-zetoni");
    } finally { c.release(); }
  });

  adminRouter.post("/agent-zetoni/:id/preklici", async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return res.status(400).json({ error: "invalid_id", message: "Invalid token id." });
    const b = req.body && typeof req.body === "object" ? req.body : {};
    const razlog = b.reason === undefined || b.reason === null ? null : String(b.reason).trim().slice(0, 500) || null;
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      const st = (await c.query("SELECT id, preklican_at FROM agent_zetoni WHERE id = $1 FOR UPDATE", [id])).rows[0];
      if (!st) { await c.query("ROLLBACK"); return res.status(404).json({ error: "not_found", message: "Token not found." }); }
      if (st.preklican_at) { await c.query("ROLLBACK"); return res.status(409).json({ error: "already_revoked", message: "Token is already revoked." }); }
      const r = (await c.query(`UPDATE agent_zetoni SET preklican_at = NOW() WHERE id = $1 RETURNING ${STOLPCI_ZETONA}`, [id])).rows[0];
      await zapisiAdminDejanje(c, req, "agent.token_revoke", "agent_zeton", id, { preklican_at: null }, { preklican_at: r.preklican_at.toISOString() }, razlog);
      await c.query("COMMIT");
      console.log(`Admin ${req.user.userId} preklical zeton agenta ${id}`);
      res.set("Cache-Control", "no-store");
      return res.json(r);   // preklic velja takoj: zeton se preveri v bazi ob vsakem klicu
    } catch (e) {
      await c.query("ROLLBACK").catch(() => {});
      return dep.odgovoriNaNapako(res, e, "POST /admin/api/agent-zetoni/:id/preklici");
    } finally { c.release(); }
  });

  // =====================================================================================================================
  // 2. /agent/api/* (samo GET, obseg beri)
  // =====================================================================================================================
  const router = express.Router();

  // dnevnik: ena vrstica na klic (tudi zavrnjen), brez zetona in brez poizvedbe
  router.use((req, res, next) => {
    const t0 = Date.now();
    res.once("close", () => {
      const pot = String(req.originalUrl || req.url || "").split("?")[0].replace(/[^\x21-\x7e]/g, "?").slice(0, 120);
      console.log(`[agent] ${req.agentId === undefined ? "-" : req.agentId} ${req.method} ${pot} ${res.writableFinished ? res.statusCode : "prekinjeno"} ${Date.now() - t0}ms`);
    });
    next();
  });

  // stikalo: AGENT_API=0 izklopi vse naenkrat (Render okolje), brez baze in brez preverjanja zetona
  router.use((req, res, next) => {
    if (process.env.AGENT_API === "0") return res.status(503).set("Retry-After", "60").json({ error: "agent_api_off", message: "The agent API is switched off." });
    next();
  });

  // zlorabe: napacni/izmisljeni zetoni ne smejo bremeniti baze; meja po IP (v tabeli omejitve, kot ostali omejevalniki). Stevec pred prijavo.
  router.use(omeji({ kljuc: "agent_ip", najvec: MEJA_IP, oknoSekund: 60,
    telo429: { error: "too_many_requests", message: "Too many requests. Please try again later." } }));

  // LASTEN semafor agenta (S1): najvec ENA zahteva agenta naenkrat v procesu, BREZ cakalne vrste (zaseden = takoj 429 agent_busy) in loceno od semaforja Martinove nadzorne
  // plosce (admin_nadzor.js): skupaj najvec 2 povezavi glavnega poola, admin pot nikoli ne caka zaradi agenta (tudi ne ob izmisljenih zetonih). Semafor drzi zahteva od oblike
  // zetona do KONCA odgovora IN do konca vseh njenih branj (prekinitev odjemalca ne sprosti semaforja, dokler poizvedba na povezavi se tece).

  const zadnjaRaba = new Map();   // id zetona -> ms zadnjega zapisa (omejitev pisanja na minuto)
  // Zapis se opravi V zahtevku (ob prvem klicu v minuti, nekaj ms), da agent skupaj nikoli ne drzi vec kot ene povezave glavnega poola; zunaj READ ONLY transakcije
  // (pisanje), z mejnima casoma (lock_timeout 1 s, statement_timeout 2 s); napaka se ne pozna odgovoru. Pogoj v SQL-u zadrzi mejo tudi med vec instancami.
  async function zapisiRabo(req, id) {
    if (req.agentPrekinjen) return;
    const zdaj = Date.now();
    const prej = zadnjaRaba.get(id);
    if (prej !== undefined && zdaj - prej < RABA_ZAPIS_MS) return;
    zadnjaRaba.set(id, zdaj);
    let c;
    vBranju++;   // delo pod semaforjem agenta
    try {
      c = await pool.connect();
      await c.query("BEGIN");
      await c.query("SET LOCAL lock_timeout = 1000");
      await c.query("SET LOCAL statement_timeout = 2000");
      await c.query("UPDATE agent_zetoni SET zadnja_raba_at = NOW() WHERE id = $1 AND (zadnja_raba_at IS NULL OR zadnja_raba_at < NOW() - INTERVAL '1 minute')", [id]);
      await c.query("COMMIT");
    } catch (e) {
      if (c) await c.query("ROLLBACK").catch(() => {});
      console.error("[agent] zadnja_raba_at ni zapisana:", e && e.message);
    } finally { if (c) c.release(); vBranju--; sprosti(); }
  }

  // 1. oblika zetona + odtis (brez baze); napacna oblika ne zasede semaforja
  router.use((req, res, next) => {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!ZETON_VZOREC.test(token)) return res.status(401).json({ error: "invalid_token", message: "Missing or invalid agent token." });
    req.zetonOdtis = crypto.createHash("sha256").update(token).digest("hex");
    next();
  });

  // 2. semafor agenta (zaseden = takoj 429, brez cakanja)
  router.use((req, res, next) => {
    if (zaseden) return res.status(429).set("Retry-After", "1").json({ error: "agent_busy", message: "Only one agent request at a time." });
    zaseden = true; zahtevekZaprt = false;
    req.agentPrekinjen = false;
    req.agent = nadzor.zaAgenta(kavljiZa(req));
    // close brez konca odgovora = odjemalec je prekinil: zahtevek ne sme zaceti nobenega novega dela (gate pred vsakim branjem, zapisom in korakom spodaj);
    // semafor se sprosti, ko je zahtevek zaprt IN ni vec nobenega tekocega dela (poizvedba, zapis, omejevalnik)
    res.once("close", () => { if (!res.writableFinished) req.agentPrekinjen = true; zahtevekZaprt = true; sprosti(); });
    next();
  });

  // 3. meja po zetonu: 300/h (AGENT_API_NA_URO); kljuc je ODTIS predlozenega zetona, zato velja PRED iskanjem v bazi (zeton nad mejo ne povzroca vec poizvedb; N1);
  // stevec v bazi, ne v pomnilniku (I15). Izmisljeni zetoni dobijo vsak svojo vrstico (omejeno z mejo po IP zgoraj in ciscenjem izteklih vrstic).
  const omejiZeton = omeji({ kljuc: "agent_zeton", najvec: MEJA_ZETON, oknoSekund: 3600, kljucIz: (req) => "agent:" + req.zetonOdtis.slice(0, 32),
    telo429: { error: "agent_rate_limited", message: "Hourly request limit for this agent token reached." } });
  router.use(async (req, res, next) => {   // omejevalnik je delo pod semaforjem: steje se, nadaljevanje po prekinitvi se ne zgodi
    let naprej = false;
    vBranju++;
    try { await omejiZeton(req, res, () => { naprej = true; }); }
    catch (e) { return next(e); }
    finally { vBranju--; sprosti(); }
    if (naprej && !req.agentPrekinjen) next();
  });

  // 4. prijava: odtis -> vrstica; napacen/preklican/potekel = 401 (isti odgovor); izpad baze = 503 (I10). Iskanje gre prek bralca agenta (READ ONLY, 2 s), ne prek
  // semaforja plosce. Preklic velja takoj (brez predpomnilnika).
  async function prijava(req, res, next) {
    let v;
    try {
      v = (await req.agent.beri((c) => c.query(
        "SELECT id, obseg, preklican_at, (velja_do > NOW()) AS veljaven FROM agent_zetoni WHERE zeton_sha256 = $1", [req.zetonOdtis]))).rows[0];
    } catch (e) { return odgovoriNapaka(res, e, "agent prijava"); }
    if (req.agentPrekinjen) return;
    if (!v) return res.status(401).json({ error: "invalid_token", message: "Missing or invalid agent token." });
    req.agentId = v.id;   // za dnevnik
    if (v.preklican_at || !v.veljaven) return res.status(401).json({ error: "invalid_token", message: "Missing or invalid agent token." });
    req.user = { role: "agent", agentZetonId: v.id, obseg: v.obseg };   // brez userId: nobena pot, ki isce uporabnika, agenta ne najde
    await zapisiRabo(req, v.id);
    if (req.agentPrekinjen) return;
    next();
  }
  router.use(prijava);

  function zahtevaj(obseg) {
    return (req, res, next) => (req.user.obseg.includes(obseg) ? next() : res.status(403).json({ error: "insufficient_scope", message: `This token lacks the "${obseg}" scope.` }));
  }
  router.use(zahtevaj("beri"));

  router.use((req, res, next) => {
    if (req.method === "GET") return next();
    res.set("Allow", "GET");
    return res.status(405).json({ error: "method_not_allowed", message: "The agent API is read-only (GET)." });
  });

  function posljiJson(res, telo) {
    res.set("Cache-Control", "no-store");
    return res.json(ocisti(telo));
  }
  const napaka400 = (res, error, message) => res.status(400).json({ error, message });
  // prekinjen zahtevek: odjemalca ni vec, odgovora ne pisemo (in tega ne sporocamo kot napake)
  const odgovoriNapaka = (res, e, kje) => (e && e.code === "AGENT_PREKINJEN" ? undefined : agentSplosno.odgovoriNapaka(res, e, kje));

  // --- danes, opozorila, racuni: isti izracun in predpomnilnik kot v panelu ---
  router.get("/danes", async (req, res) => {
    try {
      const d = await req.agent.danes();
      const rez200 = (x) => (typeof x === "string" ? x.slice(0, 200) : x);   // naslov in klub nocojsnjega dogodka: najvec 200 znakov (kopija, predpomnjeni objekt ostane nespremenjen)
      return posljiJson(res, { ...d, nocoj: Array.isArray(d.nocoj) ? d.nocoj.map((n) => ({ ...n, naslov: rez200(n.naslov), klub: rez200(n.klub) })) : d.nocoj });
    } catch (e) { return odgovoriNapaka(res, e, "GET /agent/api/danes"); }
  });
  router.get("/opozorila", async (req, res) => {
    try { return posljiJson(res, await req.agent.opozorila()); } catch (e) { return odgovoriNapaka(res, e, "GET /agent/api/opozorila"); }
  });
  router.get("/racuni", async (req, res) => {
    try { return posljiJson(res, await req.agent.racuni(req.query.stanje, req.query.limit)); }
    catch (e) {
      if (e && e.code === "NEVELJAVNO_STANJE") return napaka400(res, "invalid_stanje", e.message);
      return odgovoriNapaka(res, e, "GET /agent/api/racuni");
    }
  });

  // --- dogodki ---
  // Nasteti stolpci (I4): brez opisa, zunanje povezave za vstopnice (samo has_ticket_url) in plakata (samo has_poster: URL je tuj vnos), posnetka, naslova in koordinat prizorisca, floor_plan.
  // Besedila so odrezana ze v SQL-u (naslov dogodka nima omejitve dolzine, #330 K1): agent ne dobi niti ne obdela vec kot 200 znakov naslova, imena kluba ali prizorisca.
  const STOLPCI_DOGODKA = `e.id, e.club_id, left(c.name, 200) AS club_name, c.hidden AS club_hidden, c.is_demo AS club_is_demo, left(e.title, 200) AS title, e.status, e.start_at, e.end_at,
    e.ticket_price_cents, e.currency, e.capacity, e.sold_count, e.sales_paused, e.sales_open_at, e.sales_close_at, (e.poster_url <> '') AS has_poster, e.min_age, e.genres, e.vip_enabled,
    left(e.venue_name, 200) AS venue_name, left(e.venue_city, 200) AS venue_city, (e.ticket_url <> '') AS has_ticket_url, e.created_at`;

  // zanri samo iz znanega seznama ZANRI (tuj vnos ne pride do agenta), valuta brez presledkov
  const oblikaDogodka = (e) => ({ ...e, currency: String(e.currency).trim(), genres: (Array.isArray(e.genres) ? e.genres : []).filter((g) => ZANRI.includes(g)) });

  // Stevci prodaje po dogodkih (kot stats v GET /admin/api/events/:id): pravi in testni promet LOCENO (I39), brez guest liste (I24), samo stevila.
  async function prodajaDogodkov(c, ids) {
    const m = new Map();
    for (const id of ids) m.set(id, { paid_orders: 0, paid_cents: 0, test_paid_orders: 0, test_paid_cents: 0, pending_orders: 0, checked_in: 0 });
    if (!ids.length) return m;
    const PLACANO = `o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL`;
    const n = await c.query(
      `SELECT o.event_id,
              COUNT(*) FILTER (WHERE ${PLACANO} AND NOT ${T})::int AS paid_orders,
              COALESCE(SUM(o.total_cents - o.refunded_cents) FILTER (WHERE ${PLACANO} AND NOT ${T}), 0)::int AS paid_cents,
              COUNT(*) FILTER (WHERE ${PLACANO} AND ${T})::int AS test_paid_orders,
              COALESCE(SUM(o.total_cents - o.refunded_cents) FILTER (WHERE ${PLACANO} AND ${T}), 0)::int AS test_paid_cents,
              COUNT(*) FILTER (WHERE o.status = 'pending')::int AS pending_orders
         FROM orders o WHERE o.event_id = ANY($1::int[]) GROUP BY o.event_id`, [ids]);
    for (const x of n.rows) Object.assign(m.get(x.event_id), { paid_orders: x.paid_orders, paid_cents: x.paid_cents, test_paid_orders: x.test_paid_orders, test_paid_cents: x.test_paid_cents, pending_orders: x.pending_orders });
    const v = await c.query("SELECT t.event_id, COUNT(*)::int AS n FROM tickets t WHERE t.event_id = ANY($1::int[]) AND t.status = 'used' GROUP BY t.event_id", [ids]);
    for (const x of v.rows) m.get(x.event_id).checked_in = x.n;
    return m;
  }

  router.get("/events", async (req, res) => {
    const q = req.query;
    if (q.status !== undefined && !STATUSI_DOGODKA.includes(q.status)) return napaka400(res, "invalid_status", "status must be draft, published or cancelled.");
    if (q.od !== undefined && !veljavenDan(q.od)) return napaka400(res, "invalid_od", "od must be a date YYYY-MM-DD.");
    if (q.do !== undefined && !veljavenDan(q.do)) return napaka400(res, "invalid_do", "do must be a date YYYY-MM-DD.");
    if (q.od !== undefined && q.do !== undefined && q.od > q.do) return napaka400(res, "invalid_range", "od must not be after do.");
    const limit = Math.min(Math.max(Number.parseInt(q.limit, 10) || 50, 1), 200);
    try {
      const r = await req.agent.beri(async (c) => {
        const ev = await c.query(
          `SELECT ${STOLPCI_DOGODKA}
             FROM events e JOIN clubs c ON c.id = e.club_id
            WHERE ($1::text IS NULL OR e.status = $1)
              AND ($2::date IS NULL OR e.start_at >= ($2::date::timestamp AT TIME ZONE 'Europe/Ljubljana'))
              AND ($3::date IS NULL OR e.start_at < (($3::date + 1)::timestamp AT TIME ZONE 'Europe/Ljubljana'))
            ORDER BY e.start_at DESC, e.id DESC LIMIT $4`,
          [q.status === undefined ? null : q.status, q.od === undefined ? null : q.od, q.do === undefined ? null : q.do, limit]);
        return { ev: ev.rows, prodaja: await prodajaDogodkov(c, ev.rows.map((x) => x.id)) };
      });
      return posljiJson(res, { limit, items: r.ev.map((e) => ({ ...oblikaDogodka(e), prodaja: r.prodaja.get(e.id) })) });
    } catch (e) { return odgovoriNapaka(res, e, "GET /agent/api/events"); }
  });

  router.get("/events/:id", async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return napaka400(res, "invalid_id", "Invalid event id.");
    try {
      const r = await req.agent.beri(async (c) => {
        const ev = await c.query(`SELECT ${STOLPCI_DOGODKA} FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1`, [id]);
        if (!ev.rows.length) return null;
        return { e: ev.rows[0], prodaja: (await prodajaDogodkov(c, [id])).get(id) };
      });
      if (!r) return res.status(404).json({ error: "not_found", message: "Event not found." });
      return posljiJson(res, { event: oblikaDogodka(r.e), prodaja: r.prodaja });
    } catch (e) { return odgovoriNapaka(res, e, "GET /agent/api/events/:id"); }
  });

  // --- finance: samo seštevki (kot GET /admin/api/finance; test primerja oba) ---
  router.get("/finance", async (req, res) => {
    if (req.query.from !== undefined && !veljavenDan(req.query.from)) return napaka400(res, "invalid_from", "from must be a date YYYY-MM-DD.");
    if (req.query.to !== undefined && !veljavenDan(req.query.to)) return napaka400(res, "invalid_to", "to must be a date YYYY-MM-DD.");
    const do_ = req.query.to || new Date().toISOString().slice(0, 10);
    const od = req.query.from || new Date(Date.now() - 29 * 864e5).toISOString().slice(0, 10);
    if (od > do_) return napaka400(res, "invalid_range", "from must be before to.");
    if ((Date.parse(do_) - Date.parse(od)) / 864e5 >= RAZPON_FINANC_DNI) return napaka400(res, "range_too_large", `The range must be shorter than ${RAZPON_FINANC_DNI} days.`);
    const p = [od, do_];
    const STANJA = `o.status IN ('paid','partially_refunded','refunded')`;
    const NETO = `o.status <> 'refunded'`;
    const KJE_VSE = `${STANJA} AND o.guest_list_id IS NULL AND o.created_at >= $1::date AND o.created_at < ($2::date + INTERVAL '1 day')`;
    const KJE = `${KJE_VSE} AND NOT ${T}`;   // pravi promet
    const PLATFORMNO = SQL_NAROCILO_PLATFORMNO("o");   // I50: prodajalec je platforma (v index.js je placilaStripe definiran sele za ustvari(): zato sele tu)
    try {
      const r = await req.agent.beri(async (c) => {
        const skupaj = await c.query(
          `SELECT COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                  COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                  COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                  COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents) FILTER (WHERE NOT ${PLATFORMNO} AND ${NETO}),0)::int AS clubs_net_cents,
                  COALESCE(SUM(o.total_cents - o.refunded_cents) FILTER (WHERE ${PLATFORMNO}),0)::int AS own_sales_cents,
                  COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets_sold,
                  COUNT(*)::int AS orders,
                  COUNT(*) FILTER (WHERE o.status = 'refunded')::int AS refunded_orders,
                  COUNT(DISTINCT COALESCE(o.user_id::text, lower(o.guest_email)))::int AS buyers,
                  COUNT(DISTINCT o.club_id)::int AS clubs_with_sales
             FROM orders o WHERE ${KJE}`, p);   // buyers = SAMO stevilo (DISTINCT), nobenega naslova ne vrnemo
        const test = await c.query(
          `SELECT COUNT(*)::int AS orders,
                  COUNT(*) FILTER (WHERE o.status = 'refunded')::int AS refunded_orders,
                  COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                  COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                  COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                  COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets_sold
             FROM orders o WHERE ${KJE_VSE} AND ${T}`, p);
        const poDogodkih = await c.query(
          `SELECT e.id, left(e.title, 200) AS title, e.start_at, e.status, e.ticket_price_cents, e.capacity, e.sold_count, left(c.name, 200) AS club_name,
                  COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                  COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                  COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                  COUNT(o.id)::int AS orders,
                  COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets_sold,
                  (SELECT COUNT(*)::int FROM tickets t WHERE t.event_id = e.id AND t.status = 'used') AS checked_in
             FROM events e JOIN clubs c ON c.id = e.club_id
             LEFT JOIN orders o ON o.event_id = e.id AND ${KJE}
            GROUP BY e.id, c.name HAVING COUNT(o.id) > 0
            ORDER BY gross_cents DESC LIMIT 50`, p);
        const poDnevih = await c.query(
          `SELECT to_char(d.dan, 'YYYY-MM-DD') AS day,
                  COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                  COALESCE(SUM(o.application_fee_cents) FILTER (WHERE ${NETO}),0)::int AS fee_cents,
                  COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                  COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL AND ${NETO}),0)::int AS tickets,
                  COUNT(o.id)::int AS orders
             FROM generate_series($1::date, $2::date, '1 day') AS d(dan)
             LEFT JOIN orders o ON ${STANJA} AND o.guest_list_id IS NULL AND NOT ${T}
                  AND o.created_at >= d.dan AND o.created_at < d.dan + INTERVAL '1 day'
            GROUP BY d.dan ORDER BY d.dan`, p);
        return { skupaj: skupaj.rows[0], test: test.rows[0], poDogodkih: poDogodkih.rows, poDnevih: poDnevih.rows };
      });
      return posljiJson(res, { payments_mode: paymentsMode(), from: od, to: do_, summary: { ...r.skupaj, test_orders: r.test.orders }, test_summary: r.test, by_event: r.poDogodkih, by_day: r.poDnevih });
    } catch (e) { return odgovoriNapaka(res, e, "GET /agent/api/finance"); }
  });

  // --- dnevnik admin dejanj: BREZ e-naslova admina in brez besedil (S2: brezBesedil, ima_razlog) (admin_user_id in agent_zeton_id sta samo stevilki) ---
  router.get("/audit", async (req, res) => {
    const tip = req.query.target_type, cilj = req.query.target_id;
    if (tip !== undefined && (typeof tip !== "string" || !/^[a-z_]{1,30}$/.test(tip))) return napaka400(res, "invalid_target_type", "Invalid target_type.");
    if (cilj !== undefined && (typeof cilj !== "string" || !/^[\w-]{1,60}$/.test(cilj))) return napaka400(res, "invalid_target_id", "Invalid target_id.");
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 200);
    try {
      const r = await req.agent.beri((c) => c.query(
        `SELECT a.id, a.cas, a.dejanje, a.cilj_tip AS target_type, a.cilj_id AS target_id, a.prej, a.potem, (a.razlog IS NOT NULL) AS ima_razlog, a.admin_user_id, a.agent_zeton_id
           FROM admin_dejanja a
          WHERE ($1::text IS NULL OR a.cilj_tip = $1) AND ($2::text IS NULL OR a.cilj_id = $2)
          ORDER BY a.cas DESC, a.id DESC LIMIT $3`, [tip === undefined ? null : tip, cilj === undefined ? null : cilj, limit]));
      // S2: prej/potem brez besedil (opis, naslovi, URL-ji, kontakti = tuj vnos), razlog sploh ne gre ven (lahko vsebuje ime osebe): samo `ima_razlog`
      return posljiJson(res, { limit, items: r.rows.map((x) => ({ ...x, prej: brezBesedil(x.prej), potem: brezBesedil(x.potem) })) });
    } catch (e) { return odgovoriNapaka(res, e, "GET /agent/api/audit"); }
  });

  // vse ostalo pod /agent/api: 404 v JSON (po prijavi: neprijavljen odjemalec ne izve, katere poti obstajajo)
  router.use((req, res) => res.status(404).json({ error: "not_found", message: "Unknown agent API path." }));

  console.log(`[agent] /agent/api ${process.env.AGENT_API === "0" ? "IZKLOPLJEN (AGENT_API=0)" : "vklopljen"}: ${MEJA_ZETON}/h na zeton, ${MEJA_IP}/min na IP, 1 zahteva agenta naenkrat`);
  return { router, ocisti };
}

module.exports = { ustvari, ocisti, ocistiNiz, brezBesedil, PREDPONA, OBSEGI };
