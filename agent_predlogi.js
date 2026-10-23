"use strict";
// Predlogi agenta (Claude), ki jih potrdi admin v panelu (23. 10. 2026, issue #330, 2. del; migracija 059; ARCHITECTURE »Dostop za agenta«, invarianta I57).
// Martin 23. 10. 2026 ~01:03 UTC (outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md, razdelek 6): »Pisanje agenta: A — vse pisanje kot predlog, ki ga Martin potrdi v panelu«.
//
// Tok:
//  1. POST /agent/api/predlogi (zeton z obsegom `predlagaj`): agent zapise NAMERO. Telo gre skozi validacijo OBSTOJECE poti (urediDogodek / ustvariDogodek / podvojiDogodek
//     iz index.js v nacinu `samoPreveri`: ista funkcija, ne kopija), nato se zapise vrstica `predlogi_dejanj` (stanje caka, rok 24 h) s posnetkom spremenjenih polj (`prej`).
//     NIC se ne spremeni na cilju, nic se ne zaklene (predlog ne zaklepa `events`, ne dotakne se `orders`/`tickets`, nikoli skenPool).
//  2. Admin v panelu (zavihek »Čaka potrditev«): POST /admin/api/predlogi/:id/potrdi -> dejanje tece POD ADMINOVIM racunom po OBSTOJECI poti (isti zaklepi, iste invariante,
//     isti dnevnik), v ISTI transakciji: zaklep vrstice predloga (FOR UPDATE), preverba (caka, rok, zeton veljaven, `prej` = trenutno), prehod caka -> potrjen, vrstica
//     admin_dejanja dejanja z `predlog_id` in `agent_zeton_id`. Dvojni klik: drugi caka na zaklep in dobi 409 predlog_ne_caka.
//     /zavrni -> zavrnjen, nic se ne izvede.
//  3. Nujni nacin (#330, 3. del, NI v tem delu): ista izvedba `izvedi()` z drugim izvajalcem in lastnimi varovali; zato je izvedba locena od HTTP poti admina.
//
// Beli seznam (DEJANJA): urejanje besedila/plakata/zanrov, okno prodaje, objava (samo iz osnutka), ustavitev in zagon prodaje, nov dogodek kot osnutek, podvajanje.
// NI: cena (denar odloci Martin), kapaciteta, starost, odpoved, vracila, vloge, klubi, uporabniki, izvoz, guest liste, racuni. Isti seznam varuje CHECK v bazi (059).
// Ves vhod agenta je NEZAUPLJIV (prompt injection v opisih, imenih, razlogu): omejene dolzine in tipi, panel ga kaze samo kot besedilo, odgovor agentu gre skozi ocisti().

const DEJANJA = new Map([
  ["event.uredi",          { cilj: "event", pot: "uredi",   polja: ["title", "description", "posterUrl", "genres"] }],
  ["event.okno_prodaje",   { cilj: "event", pot: "uredi",   polja: ["salesOpenAt", "salesCloseAt"] }],
  ["event.objavi",         { cilj: "event", pot: "uredi",   polja: [], fiksno: { status: "published" } }],
  ["event.ustavi_prodajo", { cilj: "event", pot: "uredi",   polja: [], fiksno: { salesPaused: true } }],
  ["event.zazeni_prodajo", { cilj: "event", pot: "uredi",   polja: [], fiksno: { salesPaused: false } }],
  ["event.nov_osnutek",    { cilj: "club",  pot: "ustvari", polja: ["title", "description", "posterUrl", "startAt", "endAt", "genres", "venueClubId", "venueName", "venueAddress", "venueCity"] }],
  ["event.podvoji",        { cilj: "event", pot: "podvoji", polja: ["startAt", "ponovi", "n"] }],
]);
// Stolpci, ki jih urediDogodek lahko spremeni iz zgornjih polj: samo ti gredo v posnetek `prej` (imena stolpcev v SQL samo s tega seznama).
const STOLPCI_PREJ = new Set(["title", "description", "poster_url", "genres", "sales_open_at", "sales_close_at", "status", "sales_paused"]);
const STANJA = ["caka", "potrjen", "zavrnjen", "potekel", "neuspel"];
const SPREMEMBE_NAJVEC = 20000;      // znakov JSON (naslov z 95 000 znaki ne pride niti do validacije poti)
const PREJ_NAJVEC = 200000;          // znakov JSON posnetka (opis v bazi nima omejitve)
const RAZLOG_NAJVEC = 1000;
const ZAKLEP_RAZRED = 73120;         // advisory (razred, id zetona): stetje cakajocih in vstavljanje zaporedno tudi cez instance; 73110/73112 sta nakup/pavza

const veljaven = (v) => (v instanceof Date ? v.toISOString() : v === undefined ? null : v);
const enako = (a, b) => JSON.stringify(veljaven(a)) === JSON.stringify(veljaven(b));
const odgovor = (status, error, message, dodatno = {}) => Object.assign(new Error(message), { odgovor: { status, telo: { error, message, ...dodatno } } });

// Lazen `res` za validacijo po obstojeci poti: ujame status in telo napake (poti pisejo res.status(400).send/json).
function lazenOdgovor() {
  return { statusCode: 200, telo: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.telo = b; return this; },
    send(b) { this.telo = b; return this; }, set() { return this; }, setHeader() {} };
}
function opisNapake(telo) {
  if (telo && typeof telo === "object") return { koda: typeof telo.error === "string" ? telo.error : null, sporocilo: String(telo.message || telo.error || "") };
  if (typeof telo === "string") { try { return opisNapake(JSON.parse(telo)); } catch (_) { return { koda: null, sporocilo: telo }; } }
  return { koda: null, sporocilo: "" };
}

function ustvari(dep) {
  const { pool, adminRouter, omeji, zapisiAdminDejanje, celoId4, ocisti, delo, okoljeCelo, dejanja } = dep;
  const MEJA_NA_URO = okoljeCelo("AGENT_PREDLOGI_NA_URO", 30, 1, 100000);
  const CAKA_NAJVEC = okoljeCelo("AGENT_PREDLOGI_CAKA_NAJVEC", 20, 1, 1000);
  const STANJE_SQL = `CASE WHEN p.stanje = 'caka' AND p.velja_do <= NOW() THEN 'potekel' ELSE p.stanje END`;

  // Lazna zahteva za obstojeco pot (vloga admin): pri validaciji brez uporabnika, pri izvedbi z adminovim req.user (I5: vloga iz baze ob tem klicu).
  const zahtevaZa = (cilj, telo, user, predlog) => ({ params: { id: String(cilj) }, body: telo, user, klub: { clubId: null, role: "admin" }, headers: {}, predlog });

  // Telo obstojece poti iz shranjenega predloga (spremembe so ze normalizirane).
  function teloPoti(p) {
    const opis = DEJANJA.get(p.dejanje);
    return opis.pot === "ustvari" ? { ...p.spremembe, clubId: p.cilj_id } : { ...p.spremembe };
  }

  // =====================================================================================================================
  // 1. AGENT: POST/GET /agent/api/predlogi
  // =====================================================================================================================
  // Validacija + posnetek. Vrne { spremembe, prej } ali vrze e.odgovor. Bere glavni pool (kratko, brez zaklepov), pod semaforjem agenta (delo).
  async function pripravi(dejanje, opis, ciljId, vhod) {
    const telo = {};
    for (const k of opis.polja) if (Object.prototype.hasOwnProperty.call(vhod, k)) telo[k] = vhod[k];
    Object.assign(telo, opis.fiksno || {});
    const lazen = lazenOdgovor();
    let izid = null;
    if (opis.pot === "uredi") {
      await dejanja.uredi(zahtevaZa(ciljId, telo, { role: "admin" }), lazen, { samoPreveri: (dovoljeno, d) => { izid = { dovoljeno, d }; } });
    } else if (opis.pot === "ustvari") {
      await dejanja.ustvari(zahtevaZa(ciljId, { ...telo, clubId: ciljId }, { role: "admin" }), lazen, { admin: true, samoPreveri: () => { izid = {}; } });
    } else {
      const obstaja = (await pool.query("SELECT id FROM events WHERE id = $1", [ciljId])).rows[0];
      if (!obstaja) throw odgovor(404, "cilj_ni_najden", "Target not found.");
      await dejanja.podvoji(zahtevaZa(ciljId, telo, { role: "admin" }), lazen, { samoPreveri: () => { izid = {}; } });
    }
    if (!izid) {
      if (lazen.statusCode === 404) throw odgovor(404, "cilj_ni_najden", "Target not found.");
      if (lazen.statusCode >= 500) throw new Error("validacija predloga: pot je vrnila " + lazen.statusCode);
      const n = opisNapake(lazen.telo);
      throw odgovor(400, "invalid_changes", n.sporocilo.slice(0, 300) || "The changes are not valid.", { koda: n.koda });
    }
    if (opis.pot !== "uredi") return { spremembe: telo, prej: null };
    // urejanje: normalizirana polja poti (npr. zanri malo, ISO casi) + posnetek istih stolpcev (brez zaklepa)
    const spremembe = {};
    for (const [k, v] of Object.entries(izid.dovoljeno)) if (v !== undefined) spremembe[k] = v;
    const kljuci = Object.keys(spremembe);
    if (!kljuci.length) throw odgovor(400, "brez_spremembe", "Nothing to change.");
    if (kljuci.some((k) => !STOLPCI_PREJ.has(k))) throw odgovor(400, "sprememba_ni_dovoljena", "This change is not allowed for an agent proposal.");
    if (dejanje === "event.objavi" && izid.d.status !== "draft") throw odgovor(400, "objava_samo_iz_osnutka", "Only a draft event can be proposed for publishing.");
    const st = (await pool.query(`SELECT ${kljuci.map((k) => `"${k}"`).join(", ")} FROM events WHERE id = $1`, [ciljId])).rows[0];
    if (!st) throw odgovor(404, "cilj_ni_najden", "Target not found.");
    const prej = {};
    for (const k of kljuci) prej[k] = veljaven(st[k]);
    if (kljuci.every((k) => enako(prej[k], spremembe[k]))) throw odgovor(400, "brez_spremembe", "The proposal would not change anything.");
    if (JSON.stringify(prej).length > PREJ_NAJVEC) throw odgovor(400, "cilj_prevelik", "The current value is too large for a proposal.");
    return { spremembe: JSON.parse(JSON.stringify(spremembe)), prej };
  }

  // Oblika predloga za agenta: brez id-ja admina in zetona (agent vidi samo svoje), ocisceno v posljiJson.
  const STOLPCI_AGENT = `p.id, p.dejanje, p.cilj_tip, p.cilj_id, p.spremembe, p.prej, p.razlog, ${STANJE_SQL} AS stanje, p.ustvarjen_at, p.velja_do, p.odloceno_at, p.napaka`;

  function agentPoti(router, { zahtevaj, odgovoriNapaka, posljiJson }) {
    const omejiPredloge = omeji({ kljuc: "agent_predlog", najvec: MEJA_NA_URO, oknoSekund: 3600, kljucIz: (req) => "predlog:" + req.user.agentZetonId,
      telo429: { error: "agent_predlogi_rate_limited", message: "Hourly proposal limit for this agent token reached." } });

    router.get("/predlogi", zahtevaj("predlagaj"), async (req, res) => {
      const stanje = req.query.stanje;
      if (stanje !== undefined && !STANJA.includes(stanje)) return res.status(400).json({ error: "invalid_stanje", message: "stanje must be one of: " + STANJA.join(", ") + "." });
      const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 100);
      try {
        const r = await req.agent.beri((c) => c.query(
          `SELECT ${STOLPCI_AGENT} FROM predlogi_dejanj p
            WHERE p.agent_zeton_id = $1 AND ($2::text IS NULL OR ${STANJE_SQL} = $2)
            ORDER BY p.id DESC LIMIT $3`, [req.user.agentZetonId, stanje === undefined ? null : stanje, limit]));
        return posljiJson(res, { limit, items: r.rows });
      } catch (e) { return odgovoriNapaka(res, e, "GET /agent/api/predlogi"); }
    });

    router.post("/predlogi", zahtevaj("predlagaj"), async (req, res, next) => {
      // omejevalnik je delo pod semaforjem agenta (steje VSAK poskus, tudi zavrnjen: agent ne more tipati belega seznama brez meje)
      let naprej = false;
      try { await delo(req, () => omejiPredloge(req, res, () => { naprej = true; })); } catch (e) { return odgovoriNapaka(res, e, "POST /agent/api/predlogi"); }
      if (naprej && !req.agentPrekinjen) next();
    }, async (req, res) => {
      const b = req.body;
      const napaka = (status, error, message, dodatno) => res.status(status).json({ error, message, ...dodatno });
      if (!b || typeof b !== "object" || Array.isArray(b)) return napaka(400, "invalid_body", "Body must be a JSON object.");
      const opis = typeof b.dejanje === "string" ? DEJANJA.get(b.dejanje) : undefined;
      if (!opis) return napaka(400, "dejanje_ni_dovoljeno", "This action can't be proposed by an agent.", { dovoljena: [...DEJANJA.keys()] });
      const cilj = b.cilj && typeof b.cilj === "object" && !Array.isArray(b.cilj) ? b.cilj : {};
      const ciljId = typeof cilj.id === "number" || typeof cilj.id === "string" ? celoId4(cilj.id) : null;
      if (cilj.tip !== opis.cilj || !ciljId) return napaka(400, "invalid_cilj", `cilj must be { tip: "${opis.cilj}", id: <id> }.`);
      const razlog = b.razlog;
      if (typeof razlog !== "string" || razlog.trim().length < 3 || razlog.length > RAZLOG_NAJVEC || /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(razlog)) {
        return napaka(400, "invalid_reason", `razlog must be a text of 3-${RAZLOG_NAJVEC} characters without control characters.`);
      }
      const spr = b.spremembe === undefined ? {} : b.spremembe;
      if (!spr || typeof spr !== "object" || Array.isArray(spr)) return napaka(400, "invalid_spremembe", "spremembe must be a JSON object.");
      if (JSON.stringify(spr).length > SPREMEMBE_NAJVEC) return napaka(400, "spremembe_prevelike", `spremembe must be at most ${SPREMEMBE_NAJVEC} characters of JSON.`);
      const tuje = Object.keys(spr).filter((k) => !opis.polja.includes(k));
      if (tuje.length) return napaka(400, "sprememba_ni_dovoljena", "These fields can't be changed by an agent proposal.", { polja: tuje.slice(0, 10).map((k) => k.slice(0, 40)) });
      if (opis.pot === "uredi" && !opis.fiksno && !Object.keys(spr).length) return napaka(400, "brez_spremembe", "Nothing to change.");
      try {
        const pr = await delo(req, () => pripravi(b.dejanje, opis, ciljId, spr));
        const vrstica = await delo(req, async () => {
          const c = await pool.connect();
          try {
            await c.query("BEGIN");
            await c.query("SET LOCAL lock_timeout = 1000");
            await c.query("SET LOCAL statement_timeout = 2000");
            await c.query("SELECT pg_advisory_xact_lock($1::int, $2::int)", [ZAKLEP_RAZRED, req.user.agentZetonId]);
            const n = (await c.query("SELECT COUNT(*)::int AS n FROM predlogi_dejanj WHERE agent_zeton_id = $1 AND stanje = 'caka' AND velja_do > NOW()", [req.user.agentZetonId])).rows[0].n;
            if (n >= CAKA_NAJVEC) { await c.query("ROLLBACK"); throw odgovor(409, "too_many_pending", `At most ${CAKA_NAJVEC} proposals may wait for approval.`); }
            const v = (await c.query(
              `INSERT INTO predlogi_dejanj (agent_zeton_id, dejanje, cilj_tip, cilj_id, spremembe, prej, razlog)
               VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7) RETURNING id`,
              [req.user.agentZetonId, b.dejanje, opis.cilj, ciljId, JSON.stringify(pr.spremembe), pr.prej === null ? null : JSON.stringify(pr.prej), razlog])).rows[0];
            // dnevnik: brez admina, brez besedila agenta (razlog je v predlogu, ne v admin_dejanja)
            await zapisiAdminDejanje(c, { user: {}, predlog: { id: v.id, agentZetonId: req.user.agentZetonId } }, "agent.predlog", "predlog", v.id, null,
              { dejanje: b.dejanje, cilj_tip: opis.cilj, cilj_id: ciljId });
            const p = (await c.query(`SELECT ${STOLPCI_AGENT} FROM predlogi_dejanj p WHERE p.id = $1`, [v.id])).rows[0];
            await c.query("COMMIT");
            return p;
          } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
          finally { c.release(); }
        });
        console.log(`[agent] zeton ${req.user.agentZetonId} predlagal ${b.dejanje} (${opis.cilj} ${ciljId}) -> predlog ${vrstica.id}`);
        return res.status(201).set("Cache-Control", "no-store").json(ocisti({ predlog: vrstica }));
      } catch (e) {
        if (e && e.odgovor) return res.status(e.odgovor.status).json(ocisti(e.odgovor.telo));
        return odgovoriNapaka(res, e, "POST /agent/api/predlogi");
      }
    });
  }

  // =====================================================================================================================
  // 2. ADMIN: GET /admin/api/predlogi, POST /admin/api/predlogi/:id/potrdi | /zavrni (router admin: requireAuth + requireRole("admin"); zeton agenta = 403)
  // =====================================================================================================================
  adminRouter.get("/predlogi", async (req, res) => {
    const stanje = req.query.stanje === undefined ? "caka" : String(req.query.stanje);
    if (stanje !== "vse" && !STANJA.includes(stanje)) return res.status(400).json({ error: "invalid_stanje", message: "stanje must be one of: vse, " + STANJA.join(", ") + "." });
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), 200);
    try {
      const r = await pool.query(
        `SELECT p.id, p.dejanje, p.cilj_tip, p.cilj_id, p.spremembe, p.prej, p.razlog, ${STANJE_SQL} AS stanje, p.ustvarjen_at, p.velja_do,
                p.odlocil_admin_id, p.odloceno_at, p.napaka, p.agent_zeton_id, z.ime AS zeton_ime,
                (z.preklican_at IS NULL AND z.velja_do > NOW()) AS zeton_veljaven,
                CASE p.cilj_tip WHEN 'event' THEN (SELECT left(e.title, 200) FROM events e WHERE e.id = p.cilj_id)
                                WHEN 'club'  THEN (SELECT left(k.name, 200) FROM clubs k WHERE k.id = p.cilj_id) END AS cilj_naslov
           FROM predlogi_dejanj p JOIN agent_zetoni z ON z.id = p.agent_zeton_id
          WHERE ($1::text = 'vse' OR ${STANJE_SQL} = $1)
          ORDER BY p.id DESC LIMIT $2`, [stanje, limit]);
      const caka = (await pool.query("SELECT COUNT(*)::int AS n FROM predlogi_dejanj WHERE stanje = 'caka' AND velja_do > NOW()")).rows[0].n;
      res.set("Cache-Control", "no-store");
      return res.json({ stanje, caka, items: r.rows });
    } catch (e) { return dep.odgovoriNaNapako(res, e, "GET /admin/api/predlogi"); }
  });

  const razlogAdmina = (b) => (b && (b.reason === undefined || b.reason === null) ? null : String((b || {}).reason ?? "").trim().slice(0, 500) || null);

  async function zakljuci(id, stanje, napaka, adminId) {
    await pool.query("UPDATE predlogi_dejanj SET stanje = $2, napaka = $3, odlocil_admin_id = $4, odloceno_at = NOW() WHERE id = $1 AND stanje = 'caka'",
      [id, stanje, napaka === null ? null : String(napaka).slice(0, 300), adminId === undefined ? null : adminId]);
  }

  // Izvedba predloga po obstojeci poti. `req` je zahteva IZVAJALCA (admin ob kliku; kasneje nujni nacin), `res` pravi odgovor (pot ga napise sama).
  // Vrne { status, koda }. Zastarel/potekel/preklican zeton/napaka poti (400/404) zapre predlog (neuspel/potekel), zacasna napaka (503) ga pusti caka.
  async function izvedi(p, req, res, razlog) {
    const opis = DEJANJA.get(p.dejanje);
    const izvajalec = zahtevaZa(p.cilj_id, teloPoti(p), req.user, { id: p.id, agentZetonId: p.agent_zeton_id });
    // V transakciji obstojece poti (po zaklepu vrstice dogodka pri urejanju, takoj po BEGIN pri vstavljanju): zaklep predloga in prehod caka -> potrjen.
    const kavelj = async (c, st) => {
      const z = (await c.query(
        `SELECT p.stanje, (p.velja_do > NOW()) AS velja, p.prej, (z.preklican_at IS NULL AND z.velja_do > NOW()) AS zeton_velja
           FROM predlogi_dejanj p JOIN agent_zetoni z ON z.id = p.agent_zeton_id
          WHERE p.id = $1 FOR UPDATE OF p FOR SHARE OF z`, [p.id])).rows[0];
      if (!z || z.stanje !== "caka") throw odgovor(409, "predlog_ne_caka", "This proposal is no longer waiting for approval.");
      if (!z.velja) throw odgovor(409, "predlog_potekel", "This proposal has expired (24 h).");
      if (!z.zeton_velja) throw odgovor(409, "zeton_neveljaven", "The agent token that made this proposal is revoked or expired.");
      if (st && z.prej) {
        const razlicna = Object.keys(z.prej).filter((k) => !enako(st[k], z.prej[k]));
        if (razlicna.length) throw odgovor(409, "predlog_zastarel", "The target changed after the proposal was made. Nothing was changed.", { polja: razlicna });
      }
      await c.query("UPDATE predlogi_dejanj SET stanje = 'potrjen', odlocil_admin_id = $2, odloceno_at = NOW() WHERE id = $1", [p.id, req.user.userId]);
      await zapisiAdminDejanje(c, izvajalec, "agent.predlog_potrjen", "predlog", p.id, { stanje: "caka" }, { stanje: "potrjen", dejanje: p.dejanje }, razlog);
    };
    // Telo odgovora poti zadrzimo, dokler ni zapisano stanje predloga (odjemalec po odgovoru vidi koncno stanje), nato ga posljemo nespremenjenega.
    let telo, poslano = false;
    const send = res.send;
    res.send = function (x) { telo = x; poslano = true; return this; };
    let status;
    try {
      if (opis.pot === "uredi") await dejanja.uredi(izvajalec, res, { predlog: kavelj });
      else if (opis.pot === "ustvari") await dejanja.ustvari(izvajalec, res, { admin: true, predlog: kavelj });
      else await dejanja.podvoji(izvajalec, res, { predlog: kavelj });
      status = res.statusCode;
      if (status >= 400) {
        const n = opisNapake(telo);
        if (n.koda === "predlog_potekel") await zakljuci(p.id, "potekel", null, req.user.userId);
        else if (n.koda === "predlog_zastarel" || n.koda === "zeton_neveljaven") await zakljuci(p.id, "neuspel", n.koda, req.user.userId);
        else if (n.koda !== "predlog_ne_caka" && (status === 400 || status === 404 || status === 409)) await zakljuci(p.id, "neuspel", `${status} ${n.koda || n.sporocilo}`.trim(), req.user.userId);
      }
    } finally {
      res.send = send;
      if (poslano) res.send(telo);
    }
    return { status };
  }

  adminRouter.post("/predlogi/:id/potrdi", async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return res.status(400).json({ error: "invalid_id", message: "Invalid proposal id." });
    const razlog = razlogAdmina(req.body);
    try {
      const p = (await pool.query(
        `SELECT p.id, p.agent_zeton_id, p.dejanje, p.cilj_tip, p.cilj_id, p.spremembe, p.stanje, (p.velja_do > NOW()) AS velja,
                (z.preklican_at IS NULL AND z.velja_do > NOW()) AS zeton_velja
           FROM predlogi_dejanj p JOIN agent_zetoni z ON z.id = p.agent_zeton_id WHERE p.id = $1`, [id])).rows[0];
      if (!p) return res.status(404).json({ error: "not_found", message: "Proposal not found." });
      if (p.stanje !== "caka") return res.status(409).json({ error: "predlog_ne_caka", message: "This proposal is no longer waiting for approval.", stanje: p.stanje });
      // Hitri preverbi brez zaklepa (zapiseta stanje); merodajna je ponovna preverba pod zaklepom v transakciji poti (kavelj).
      if (!p.velja) { await zakljuci(id, "potekel", null, req.user.userId); return res.status(409).json({ error: "predlog_potekel", message: "This proposal has expired (24 h)." }); }
      if (!p.zeton_velja) {
        await zakljuci(id, "neuspel", "zeton_neveljaven", req.user.userId);
        return res.status(409).json({ error: "zeton_neveljaven", message: "The agent token that made this proposal is revoked or expired. Make the change yourself if it is still needed." });
      }
      const izid = await izvedi(p, req, res, razlog);
      if (izid.status < 400) console.log(`Admin ${req.user.userId} potrdil predlog agenta ${id} (${p.dejanje}, ${p.cilj_tip} ${p.cilj_id}, zeton ${p.agent_zeton_id})`);
    } catch (e) {
      if (res.headersSent) { console.error("[predlogi] po odgovoru:", e && e.message); return; }
      return dep.odgovoriNaNapako(res, e, "POST /admin/api/predlogi/:id/potrdi");
    }
  });

  adminRouter.post("/predlogi/:id/zavrni", async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return res.status(400).json({ error: "invalid_id", message: "Invalid proposal id." });
    const razlog = razlogAdmina(req.body);
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      const p = (await c.query("SELECT id, stanje, agent_zeton_id, dejanje FROM predlogi_dejanj WHERE id = $1 FOR UPDATE", [id])).rows[0];
      if (!p) { await c.query("ROLLBACK"); return res.status(404).json({ error: "not_found", message: "Proposal not found." }); }
      if (p.stanje !== "caka") { await c.query("ROLLBACK"); return res.status(409).json({ error: "predlog_ne_caka", message: "This proposal is no longer waiting for approval.", stanje: p.stanje }); }
      await c.query("UPDATE predlogi_dejanj SET stanje = 'zavrnjen', odlocil_admin_id = $2, odloceno_at = NOW() WHERE id = $1", [id, req.user.userId]);
      await zapisiAdminDejanje(c, { user: req.user, predlog: { id, agentZetonId: p.agent_zeton_id } }, "agent.predlog_zavrnjen", "predlog", id,
        { stanje: "caka" }, { stanje: "zavrnjen", dejanje: p.dejanje }, razlog);
      const v = (await c.query(`SELECT p.id, p.dejanje, p.cilj_tip, p.cilj_id, p.stanje, p.odlocil_admin_id, p.odloceno_at FROM predlogi_dejanj p WHERE p.id = $1`, [id])).rows[0];
      await c.query("COMMIT");
      console.log(`Admin ${req.user.userId} zavrnil predlog agenta ${id}`);
      return res.json({ predlog: v });
    } catch (e) {
      await c.query("ROLLBACK").catch(() => {});
      return dep.odgovoriNaNapako(res, e, "POST /admin/api/predlogi/:id/zavrni");
    } finally { c.release(); }
  });

  console.log(`[agent] predlogi: ${MEJA_NA_URO}/h na zeton, najvec ${CAKA_NAJVEC} cakajocih na zeton, rok 24 h`);
  return { agentPoti, izvedi, DEJANJA };
}

module.exports = { ustvari, DEJANJA };
