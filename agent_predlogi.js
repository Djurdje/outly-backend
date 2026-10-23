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
//  3. Nujni nacin (#330, 3. del; migracija 060, I58): POST /agent/api/predlogi/:id/izvedi-nujno { potrditev, seja } (zeton z obsegom `nujno`): ISTA izvedba `izvedi()`
//     (ista pot, isti zaklepi, isti kavelj: caka, rok, zeton, zastarelost, enkratnost) z izvajalcem »agent v nujnem nacinu« (brez userId; pravice = klubski kontekst
//     admina kot pri potrditvi v panelu, nic vec) in lastnimi varovali v isti transakciji: predlog mlajsi od 1 h, obseg `nujno` pod zaklepom, meja 3 na 24 h GLOBALNO
//     (advisory zaklep 73121 + stetje), izkljucena dejanja (izvoz baze, vloga admin/backup) PRED belim seznamom. Mail Martinu vsaj enkrat (rezervacija pred Resendom, ponovitve, alarm).
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
// Besedila, ki morajo biti niz (obstojeca PATCH pot sprejme npr. opis null/stevilo; predlog je strozji, pot ostane nespremenjena za iOS/splet).
const BESEDILNA = new Set(["title", "description", "venueName", "venueAddress", "venueCity", "posterUrl"]);
// Bidi kontrolni znaki in znaki nicelne sirine: z njimi bi agent besedilo v panelu prikazal drugace, kot je shranjeno (prevara pri »prej -> potem«).
// (pregled #340 N2/N2b: tudi U+061C arabska oznaka smeri, U+00AD mehki vezaj, U+034F, locila vrstice/odstavka U+2028/U+2029, U+2060-U+2064)
const NEVIDNI = /[\u00AD\u034F\u061C\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/;
const imaNevidne = (v, g = 0) => (typeof v === "string" ? NEVIDNI.test(v) : v && typeof v === "object" && g < 5 ? Object.entries(v).some(([k, x]) => NEVIDNI.test(k) || imaNevidne(x, g + 1)) : false);
// Plakat v predlogu samo iz NASEGA Cloudinaryja (kot avatar, PUT /me/avatar): agent ne more podtakniti slike s tujega gostitelja (sledenje, vsebina).
// Obstojeca pot (PATCH /events/:id, iOS/splet) sprejme vsak http(s) in ostane, kot je.
// Pregled #340 S1b: predpona na surovem nizu ni dovolj (`/<oblak>/../drugi/`, `%2e%2e`, `image/fetch/https://tuj`): razclenjen URL, tocen gostitelj, brez
// vrat/uporabnika/query/hash, brez `..` in kodiranih `.`/`/`/`\` (surovo in v poti), samo dostava `/<oblak>/image/upload/`.
const NEVARNA_POT = /\.\.|%2e|%2f|%5c|\\/i;
function plakatDovoljen(url) {
  if (url === undefined || url === null || url === "") return true;
  const oblak = process.env.CLOUDINARY_CLOUD_NAME;
  if (!oblak || !/^[A-Za-z0-9_-]{1,100}$/.test(oblak) || typeof url !== "string" || NEVARNA_POT.test(url)) return false;
  let u;
  try { u = new URL(url); } catch (_) { return false; }
  return u.protocol === "https:" && u.hostname === "res.cloudinary.com" && !u.port && !u.username && !u.password && !u.search && !u.hash && !url.includes("?") && !url.includes("#")
    && !NEVARNA_POT.test(u.pathname) && u.pathname.startsWith("/" + oblak + "/image/upload/") && url === u.href;
}
const NUJNO_ZAKLEP_RAZRED = 73121;   // advisory (razred, 0): GLOBALNO zaporedje nujnih izvedb (stetje meje 3/24 h in zapis nujno_at v isti transakciji, tudi cez instance)
const NUJNO_STAROST_MIN = 60;        // nujno se izvede samo predlog, mlajsi od 1 h (nacrt 3.3 tocka 3): potrditev se nanasa na predlog, ki ga je Martin pravkar videl
const POTRDITEV_MIN = 3, POTRDITEV_NAJVEC = 1000, SEJA_NAJVEC = 500;
const NUJNO_MAIL_POSKUSOV = 5;
const NUJNO_NE_ZAPRE = new Set(["predlog_prestar", "nujno_meja", "insufficient_scope"]);   // zavrnitev nujne poti ne zapre predloga: Martin ga se lahko potrdi v panelu
const RE_SEJA = /^https:\/\/claude\.ai\/[A-Za-z0-9._~\/?#=&%:+-]{1,480}$/;
const RE_KONTROLNI = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/;   // dovoljena sta tab in nova vrstica (citat)

// IZKLJUCENO TUDI V NUJNEM NACINU (Martin 23. 10. 2026, »Da izkljuci«): (a) izvoz baze (osebni podatki, HQ pravilo 8), (b) dodelitev vloge `admin` ali `backup`.
// Preverba je v nujni poti PRED belim seznamom (DEJANJA) in neodvisna od njega: tudi ce bi kdo tako dejanje kdaj dodal na beli seznam predlogov (in v CHECK 059),
// ga nujna pot zavrne (403 nujno_izkljuceno). Ti dve gresta samo prek Martinovega klika v panelu.
const VLOGE_IZKLJUCENE = new Set(["admin", "backup"]);
function imaIzkljucenoVlogo(v, kljuc = "", globina = 0) {
  if (globina > 20) return true;   // nenavadno globoko = ne tvegamo
  if (typeof v === "string") return /role|vlog/i.test(kljuc) && VLOGE_IZKLJUCENE.has(v.trim().toLowerCase());
  if (!v || typeof v !== "object") return false;
  if (Array.isArray(v)) return v.some((x) => imaIzkljucenoVlogo(x, kljuc, globina + 1));
  return Object.entries(v).some(([k, x]) => imaIzkljucenoVlogo(x, k, globina + 1));
}
const NUJNO_IZKLJUCENO = [
  ["izvoz baze", (dejanje) => /(^|[._:-])(export|izvoz|dump|backup|kopija)([._:-]|$)/i.test(dejanje)],
  ["vloga admin/backup", (dejanje, spremembe) => imaIzkljucenoVlogo(spremembe) ||
    (/(^|[._:-])(role|roles|vloga|vloge)([._:-]|$)/i.test(dejanje) && JSON.stringify(spremembe ?? null).toLowerCase().match(/"(admin|backup)"/) !== null)],
];
function nujnoIzkljuceno(dejanje, spremembe) {
  const d = typeof dejanje === "string" ? dejanje : "";
  const z = NUJNO_IZKLJUCENO.find(([, ujema]) => ujema(d, spremembe));
  return z ? z[0] : null;
}

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
  // nujni nacin (060, I58): meja na 24 h se z okoljem lahko samo ZNIZA (0 = nobena nujna izvedba), nad Martinovih 3 ne
  const NUJNO_NA_24H = okoljeCelo("AGENT_NUJNO_NA_24H", 3, 0, 3);
  const NUJNO_MAIL_PONOVI_MS = okoljeCelo("AGENT_NUJNO_MAIL_PONOVI_MS", 120000, 100, 3600000);
  const NUJNO_MAIL_PREMOR_MS = okoljeCelo("AGENT_NUJNO_MAIL_PREMOR_MS", 60000, 0, 3600000);
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
      const klub = (await pool.query("SELECT id FROM clubs WHERE id = $1", [ciljId])).rows[0];
      if (!klub) throw odgovor(404, "cilj_ni_najden", "Target not found.");
      await dejanja.ustvari(zahtevaZa(ciljId, { ...telo, clubId: ciljId }, { role: "admin" }), lazen, { admin: true, samoPreveri: () => { izid = {}; } });
    } else {
      const obstaja = (await pool.query("SELECT id FROM events WHERE id = $1", [ciljId])).rows[0];
      if (!obstaja) throw odgovor(404, "cilj_ni_najden", "Target not found.");
      await dejanja.podvoji(zahtevaZa(ciljId, telo, { role: "admin" }), lazen, { samoPreveri: () => { izid = {}; } });
    }
    if (!izid) {
      if (lazen.statusCode === 404 && opis.pot === "ustvari") throw odgovor(400, "invalid_changes", "Venue club not found.", { koda: "venue_club_not_found" });   // cilj (klub) obstaja, manjka gostitelj
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
  const STOLPCI_AGENT = `p.id, p.dejanje, p.cilj_tip, p.cilj_id, p.spremembe, p.prej, p.razlog, ${STANJE_SQL} AS stanje, p.ustvarjen_at, p.velja_do, p.odloceno_at, p.napaka, p.nujno_at`;

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
      if (typeof razlog !== "string" || razlog.trim().length < 3 || razlog.length > RAZLOG_NAJVEC || /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(razlog) || NEVIDNI.test(razlog)) {
        return napaka(400, "invalid_reason", `razlog must be a text of 3-${RAZLOG_NAJVEC} characters without control characters.`);
      }
      const spr = b.spremembe === undefined ? {} : b.spremembe;
      if (!spr || typeof spr !== "object" || Array.isArray(spr)) return napaka(400, "invalid_spremembe", "spremembe must be a JSON object.");
      if (JSON.stringify(spr).length > SPREMEMBE_NAJVEC) return napaka(400, "spremembe_prevelike", `spremembe must be at most ${SPREMEMBE_NAJVEC} characters of JSON.`);
      const tuje = Object.keys(spr).filter((k) => !opis.polja.includes(k));
      if (tuje.length) return napaka(400, "sprememba_ni_dovoljena", "These fields can't be changed by an agent proposal.", { polja: tuje.slice(0, 10).map((k) => k.slice(0, 40)) });
      // N8: opis null = »pocisti opis« (stolpec je NOT NULL DEFAULT ''; obstojeca pot bi z null padla v bazi)
      if (spr.description === null) spr.description = "";
      const napacenTip = Object.keys(spr).filter((k) => BESEDILNA.has(k) && typeof spr[k] !== "string" && !(k === "posterUrl" && spr[k] === null));
      if (napacenTip.length) return napaka(400, "neveljaven_tip", "These fields must be text.", { polja: napacenTip });
      if (imaNevidne(spr)) return napaka(400, "nevidni_znaki", "Invisible or bidirectional control characters are not allowed in a proposal.");
      if (opis.pot === "uredi" && !opis.fiksno && !Object.keys(spr).length) return napaka(400, "brez_spremembe", "Nothing to change.");
      try {
        const pr = await delo(req, () => pripravi(b.dejanje, opis, ciljId, spr));
        if (!plakatDovoljen(opis.pot === "uredi" ? pr.spremembe.poster_url : spr.posterUrl)) {
          return napaka(400, "plakat_ni_dovoljen", "A proposed poster must be an https image uploaded to Outly's Cloudinary (res.cloudinary.com).");
        }
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

    // NUJNI NACIN (060, I58): agent izvede SVOJ predlog z Martinovo pisno potrditvijo (citat iz seje Claude Code). Stikalo in prejemnik maila sta preverjena ze v
    // agent_api.js PRED bazo (nujnoStikalo); tu obseg, telo, izkljucena dejanja, nato ista izvedba kot potrditev admina (izvedi) pod semaforjem agenta.
    router.post("/predlogi/:id/izvedi-nujno", zahtevaj("predlagaj"), zahtevaj("nujno"), async (req, res) => {
      const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
      const napaka = (status, error, message, dodatno) => res.status(status).json({ error, message, ...dodatno });
      const id = celoId4(req.params.id);
      if (!id) return napaka(400, "invalid_id", "Invalid proposal id.");
      const potrditev = typeof b.potrditev === "string" ? b.potrditev.replace(/\r\n?/g, "\n").trim() : "";
      // dolzina v ZNAKIH Unicode (kot char_length v CHECK 060: emoji = 1), brez kontrolnih in nevidnih/bidi znakov (isti NEVIDNI kot za predlog: citat v panelu in mailu
      // ne sme izgledati drugace, kot je shranjen)
      const dolzina = [...potrditev].length;
      if (dolzina < POTRDITEV_MIN || dolzina > POTRDITEV_NAJVEC || RE_KONTROLNI.test(potrditev) || NEVIDNI.test(potrditev)) {
        return napaka(400, "invalid_potrditev", `potrditev must be Martin's written confirmation, quoted verbatim (${POTRDITEV_MIN}-${POTRDITEV_NAJVEC} characters).`);
      }
      const seja = typeof b.seja === "string" ? b.seja.trim() : "";
      if (seja.length > SEJA_NAJVEC || !RE_SEJA.test(seja)) return napaka(400, "invalid_seja", "seja must be the link of the Claude Code session (https://claude.ai/...).");
      try {
        const p = await delo(req, async () => (await pool.query(
          `SELECT p.id, p.agent_zeton_id, p.dejanje, p.cilj_tip, p.cilj_id, p.spremembe, p.stanje, (p.velja_do > NOW()) AS velja,
                  (p.ustvarjen_at > NOW() - make_interval(mins => $2::int)) AS mlad
             FROM predlogi_dejanj p WHERE p.id = $1`, [id, NUJNO_STAROST_MIN])).rows[0]);
        if (!p || p.agent_zeton_id !== req.user.agentZetonId) return napaka(404, "not_found", "Proposal not found.");   // samo lastni predlogi (kot GET /predlogi)
        // Izkljuceno TUDI v nujnem nacinu (Martin »Da izkljuci«): PRED belim seznamom, neodvisno od njega.
        const izkljuceno = nujnoIzkljuceno(p.dejanje, p.spremembe);
        if (izkljuceno) {
          console.error(`[agent-nujno] POZOR: zeton ${req.user.agentZetonId} je poskusil nujno izvesti izkljuceno dejanje (${izkljuceno}), predlog ${p.id}; zavrnjeno`);
          return napaka(403, "nujno_izkljuceno", `Never in emergency mode (${izkljuceno}): only Martin, by clicking in the panel.`);
        }
        if (!DEJANJA.has(p.dejanje)) return napaka(400, "dejanje_ni_dovoljeno", "This action can't be run by an agent.");
        // Iste varovalke predloga kot ob POST /predlogi (#340: nevidni znaki, plakat samo iz nasega Cloudinaryja) se enkrat nad SHRANJENIMI spremembami
        // (vrstica bi lahko nastala mimo poti ali pred spremembo okolja); validacijo obstojece poti (naslov, URL, okno) ponovi izvedba sama.
        const sprN = p.spremembe && typeof p.spremembe === "object" && !Array.isArray(p.spremembe) ? p.spremembe : {};
        if (imaNevidne(sprN)) return napaka(400, "nevidni_znaki", "Invisible or bidirectional control characters are not allowed in a proposal.");
        if (!plakatDovoljen(sprN.poster_url !== undefined ? sprN.poster_url : sprN.posterUrl)) {
          return napaka(400, "plakat_ni_dovoljen", "A proposed poster must be an https image uploaded to Outly's Cloudinary (res.cloudinary.com).");
        }
        if (p.stanje !== "caka") return napaka(409, "predlog_ne_caka", "This proposal is no longer waiting for approval.", { stanje: p.stanje });
        if (!p.velja) return napaka(409, "predlog_potekel", "This proposal has expired (24 h).");
        if (!p.mlad) return napaka(409, "predlog_prestar", `Emergency mode only runs proposals younger than ${NUJNO_STAROST_MIN} minutes. Make a new proposal and show it to Martin.`);
        // ista izvedba kot »Potrdi« v panelu; izvajalec je agent (brez userId), klubski kontekst admina = iste pravice kot potrditev admina, ne vec (I5)
        const izvajalecReq = { user: { role: "agent", agentZetonId: req.user.agentZetonId, userId: null, nujno: true } };
        const lazen = lazenOdgovorPoti();
        const izid = await delo(req, () => izvedi(p, izvajalecReq, lazen, null, { potrditev, seja, zetonId: req.user.agentZetonId }));
        if (izid.status >= 400) {
          const n = opisNapake(lazen.telo);
          const telo = lazen.telo && typeof lazen.telo === "object" ? lazen.telo : (() => { try { return JSON.parse(lazen.telo); } catch (_) { return { error: n.koda || "napaka_poti", message: n.sporocilo }; } })();
          if (izid.status >= 500) {
            return res.status(503).set("Retry-After", "5").json({ error: "service_unavailable", message: "Temporary problem. Check GET /agent/api/predlogi before trying again." });
          }
          return res.status(izid.status).set("Cache-Control", "no-store").json(ocisti(telo));
        }
        console.log(`[agent-nujno] zeton ${req.user.agentZetonId} je NUJNO izvedel predlog ${p.id} (${p.dejanje}, ${p.cilj_tip} ${p.cilj_id})`);
        const v = await delo(req, async () => (await pool.query(`SELECT ${STOLPCI_AGENT} FROM predlogi_dejanj p WHERE p.id = $1`, [p.id])).rows[0]).catch(() => ({ id: p.id, stanje: "potrjen" }));
        res.status(200).set("Cache-Control", "no-store").json(ocisti({ izvedeno: true, predlog: v }));
        // mail takoj po odgovoru (ne caka nanj); pospravljalec ga poslje, ce ta klic ne uspe (rezervacija prepreci dvojnik)
        void nujnoMailPoslji(p.id).catch((e) => console.error("[agent-nujno] mail:", e && e.message));
        return;
      } catch (e) {
        if (e && e.odgovor) return res.status(e.odgovor.status).json(ocisti(e.odgovor.telo));
        return odgovoriNapaka(res, e, "POST /agent/api/predlogi/:id/izvedi-nujno");
      }
    });
  }

  // Lazen odgovor za izvedbo v nujnem nacinu: telo poti (vrstica dogodka za admina, lahko z opisom = tuj vnos) NE gre agentu; agent dobi samo stanje predloga.
  // json() gre skozi send() (kot v Expressu), da izvedi() prestreze telo napake.
  function lazenOdgovorPoti() {
    return { statusCode: 200, telo: undefined, headersSent: false, status(c) { this.statusCode = c; return this; }, json(b) { return this.send(JSON.stringify(b)); },
      send(b) { this.telo = b; return this; }, set() { return this; }, setHeader() {}, type() { return this; } };
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

  // Izvedba predloga po obstojeci poti. `req` je zahteva IZVAJALCA (admin ob kliku; agent v nujnem nacinu), `res` odgovor (pot ga napise sama; pri nujnem nacinu lazen).
  // Vrne { status, koda }. Zastarel/potekel/preklican zeton/napaka poti (400/404) zapre predlog (neuspel/potekel), zacasna napaka (503) ga pusti caka.
  // `nujno` (060, I58): { potrditev, seja, zetonId } -> v istem kavlju se varovala nujnega nacina (starost, obseg, meja 3/24 h) in zapis citata; NULL = potrditev admina.
  async function izvedi(p, req, res, razlog, nujno = null) {
    const opis = DEJANJA.get(p.dejanje);
    const sled = { id: p.id, agentZetonId: p.agent_zeton_id };
    if (nujno) Object.assign(sled, { nujno: true, razlogNujno: razlogNujno(p.agent_zeton_id, nujno) });
    const izvajalec = zahtevaZa(p.cilj_id, teloPoti(p), req.user, sled);
    // V transakciji obstojece poti (po zaklepu vrstice dogodka pri urejanju, takoj po BEGIN pri vstavljanju): zaklep predloga in prehod caka -> potrjen.
    // nujni nacin (N2): globalni advisory zaklep 73121 PRVI (pri urejanju takoj po BEGIN, pred vrstico dogodka; pri vstavljanju je kavelj prvi korak transakcije).
    // Vrstni red nujne izvedbe: 73121 -> vrstica dogodka -> 73112 (pavza) -> predlog -> zeton. Nihce drug 73121 ne jemlje (potrditev admina, nakup, pavza ne),
    // zato krog zaklepov ni mogoc; nujni klic ne drzi vrstice dogodka, medtem ko caka na drugo nujno izvedbo.
    const zaklepNujno = (c) => c.query("SELECT pg_advisory_xact_lock($1::int, 0)", [NUJNO_ZAKLEP_RAZRED]);
    const kavelj = async (c, st) => {
      if (nujno) await zaklepNujno(c);   // ponovni prevzem v isti transakciji je brez ucinka (pri urejanju ze vzet v predZaklepom)
      const z = (await c.query(
        `SELECT p.stanje, (p.velja_do > NOW()) AS velja, p.prej, (z.preklican_at IS NULL AND z.velja_do > NOW()) AS zeton_velja,
                p.agent_zeton_id, ('nujno' = ANY (z.obseg)) AS zeton_nujno, (p.ustvarjen_at > NOW() - make_interval(mins => $2::int)) AS mlad
           FROM predlogi_dejanj p JOIN agent_zetoni z ON z.id = p.agent_zeton_id
          WHERE p.id = $1 FOR UPDATE OF p FOR SHARE OF z`, [p.id, NUJNO_STAROST_MIN])).rows[0];
      if (!z || z.stanje !== "caka") throw odgovor(409, "predlog_ne_caka", "This proposal is no longer waiting for approval.");
      if (!z.velja) throw odgovor(409, "predlog_potekel", "This proposal has expired (24 h).");
      if (!z.zeton_velja) throw odgovor(409, "zeton_neveljaven", "The agent token that made this proposal is revoked or expired.");
      if (nujno) {
        // ponovna preverba POD ZAKLEPOM (hitre preverbe na poti so brez zaklepa): lasten predlog, obseg `nujno`, starost < 1 h
        if (z.agent_zeton_id !== nujno.zetonId || !z.zeton_nujno) throw odgovor(403, "insufficient_scope", "This token can't run this proposal in emergency mode.");
        if (!z.mlad) throw odgovor(409, "predlog_prestar", `Emergency mode only runs proposals younger than ${NUJNO_STAROST_MIN} minutes. Make a new proposal and show it to Martin.`);
      }
      if (st && z.prej) {
        const razlicna = Object.keys(z.prej).filter((k) => !enako(st[k], z.prej[k]));
        if (razlicna.length) throw odgovor(409, "predlog_zastarel", "The target changed after the proposal was made. Nothing was changed.", { polja: razlicna });
      }
      if (nujno) {
        // Meja 3 na 24 h GLOBALNO (ne na zeton): advisory zaklep do konca transakcije zaporedi vse nujne izvedbe (tudi cez instance); stetje in zapis nujno_at sta
        // v isti transakciji kot sprememba, zato 4 hkratni klici dajo natanko 3 izvedbe. Zaklep se vzame ZADNJI (po vrstici dogodka in predloga): brez krozenja.
        // zaklep 73121 je ze vzet (zgoraj): stetje in zapis nujno_at sta zaporedna cez vse instance
        const n = (await c.query("SELECT COUNT(*)::int AS n FROM predlogi_dejanj WHERE nujno_at > NOW() - INTERVAL '24 hours'")).rows[0].n;
        if (n >= NUJNO_NA_24H) throw odgovor(429, "nujno_meja", `At most ${NUJNO_NA_24H} emergency actions in 24 hours. Put the proposal in the panel for Martin.`);
        await c.query(
          `UPDATE predlogi_dejanj SET stanje = 'potrjen', odlocil_admin_id = NULL, odloceno_at = NOW(), nujno_potrditev = $2, nujno_seja = $3, nujno_at = NOW() WHERE id = $1`,
          [p.id, nujno.potrditev, nujno.seja]);
        await zapisiAdminDejanje(c, izvajalec, "agent.predlog_nujno", "predlog", p.id, { stanje: "caka" }, { stanje: "potrjen", dejanje: p.dejanje, nujno: true },
          sled.razlogNujno);
        return;
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
      if (opis.pot === "uredi") await dejanja.uredi(izvajalec, res, nujno ? { predlog: kavelj, predZaklepom: zaklepNujno } : { predlog: kavelj });
      else if (opis.pot === "ustvari") await dejanja.ustvari(izvajalec, res, { admin: true, predlog: kavelj });
      else await dejanja.podvoji(izvajalec, res, { predlog: kavelj });
      status = res.statusCode;
      if (status >= 400) {
        const n = opisNapake(telo);
        if (NUJNO_NE_ZAPRE.has(n.koda)) { /* varovalo nujnega nacina: predlog ostane caka (Martin ga lahko potrdi v panelu) */ }
        else if (n.koda === "predlog_potekel") await zakljuci(p.id, "potekel", null, req.user.userId);
        else if (n.koda === "predlog_zastarel" || n.koda === "zeton_neveljaven") await zakljuci(p.id, "neuspel", n.koda, req.user.userId ?? null);
        else if (n.koda !== "predlog_ne_caka" && (status === 400 || status === 404 || status === 409)) await zakljuci(p.id, "neuspel", `${status} ${n.koda || n.sporocilo}`.trim(), req.user.userId ?? null);
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

  // =====================================================================================================================
  // 3. NUJNI NACIN: stikalo, sled, mail Martinu, rdec pas v panelu (060, I58)
  // =====================================================================================================================
  const prejemnikiNujno = () => String(process.env.AGENT_NUJNO_MAIL || "").split(",").map((x) => x.trim()).filter((x) => /^[^@\s]+@[^@\s]+$/.test(x));
  // Pred bazo (agent_api.js): AGENT_NUJNO=0 -> izklopljeno; brez prejemnika ali brez Resenda -> izklopljeno (FAIL-CLOSED: brez obvestila Martinu ni nujne izvedbe).
  function nujnoStikalo() {
    if (process.env.AGENT_NUJNO === "0") return { error: "nujno_off", message: "Emergency mode is switched off (AGENT_NUJNO=0). Put the proposal in the panel." };
    if (!prejemnikiNujno().length || !dep.imaResend()) {
      return { error: "nujno_brez_obvestila", message: "Emergency mode is off: Martin can't be notified (AGENT_NUJNO_MAIL or Resend is not set). Put the proposal in the panel." };
    }
    return null;
  }
  // admin_dejanja.razlog (najvec 500 znakov): citat in seja; celoten citat je v predlogi_dejanj.nujno_potrditev
  function razlogNujno(zetonId, n) {
    const rep = ` | seja: ${n.seja}`;
    const glava = `NUJNO (agent, zeton #${zetonId}); potrditev: «`;
    const prostor = Math.max(10, 500 - glava.length - rep.length - 2);
    const znaki = [...n.potrditev];   // rezanje po znakih Unicode (CHECK admin_dejanja.razlog steje char_length; brez polovice para UTF-16)
    const citat = znaki.length > prostor ? znaki.slice(0, prostor - 1).join("") + "…" : n.potrditev;
    return [...(glava + citat + "»" + rep)].slice(0, 500).join("");
  }

  const OZNAKE = { "event.uredi": "Uredi dogodek", "event.okno_prodaje": "Okno prodaje", "event.objavi": "Objavi dogodek", "event.ustavi_prodajo": "Ustavi prodajo",
    "event.zazeni_prodajo": "Zaženi prodajo", "event.nov_osnutek": "Nov dogodek (osnutek)", "event.podvoji": "Podvoji dogodek" };
  const kratko = (v) => { const t = v === undefined || v === null ? "—" : typeof v === "string" ? v : JSON.stringify(v); return t.length > 300 ? t.slice(0, 300) + " …" : t; };
  // Mail Martinu: kaj, prej -> potem, citat, seja, cas. Brez podatkov kupcev (orders/users se ne berejo). Besedila (naslov dogodka) so tuj vnos: v HTML ubezana.
  function nujnoMailVsebina(p) {
    const u = dep.ubeziHtml;
    const kaj = `${OZNAKE[p.dejanje] || p.dejanje} (${p.dejanje})`;
    const cilj = `${p.cilj_tip === "club" ? "klub" : "dogodek"} #${p.cilj_id}${p.cilj_naslov ? ` — ${String(p.cilj_naslov).slice(0, 200)}` : ""}`;
    const spr = p.spremembe && typeof p.spremembe === "object" ? p.spremembe : {};
    const vrstice = Object.keys(spr).map((k) => [k, p.prej && typeof p.prej === "object" && k in p.prej ? kratko(p.prej[k]) : "—", kratko(spr[k])]);
    // pri urejanju so kljuci `prej` imena stolpcev, kljuci `spremembe` pa normalizirana polja poti (iste kljuce); fiksna dejanja (pavza, objava) imajo spremembe v `prej`
    if (!vrstice.length && p.prej && typeof p.prej === "object") for (const k of Object.keys(p.prej)) vrstice.push([k, kratko(p.prej[k]), "(sprememba dejanja)"]);
    const cas = new Date(p.nujno_at);
    const casBesedilo = `${cas.toLocaleString("sl-SI", { timeZone: "Europe/Ljubljana" })} (Ljubljana) · ${cas.toISOString()}`;
    const panel = "https://outly-backend-roy3.onrender.com/admin/";
    const zadeva = `Agent je izvedel nujno dejanje #${p.id}: ${OZNAKE[p.dejanje] || p.dejanje}`;
    const besedilo = [
      "Agent (Claude) je v NUJNEM NAČINU izvedel dejanje brez tvojega klika v panelu, s sklicem na tvojo pisno potrditev.", "",
      `Dejanje: ${kaj}`, `Cilj: ${cilj}`, "Prej → potem:", ...vrstice.map(([k, a, b]) => `  ${k}: ${a} → ${b}`), "",
      `Tvoja potrditev (citat, kot ga je poslal agent): «${p.nujno_potrditev}»`, `Seja: ${p.nujno_seja}`, `Čas: ${casBesedilo}`,
      `Žeton agenta: #${p.agent_zeton_id}${p.zeton_ime ? ` (${p.zeton_ime})` : ""}`, "",
      "Če te potrditve NISI napisal ti v tej seji: takoj prekliči žeton (panel → Agent) in preveri dejanje.",
      `Panel (rdeč pas na vrhu ostane, dokler ne klikneš »Pregledal sem«): ${panel}`,
    ].join("\n");
    const vr = (k, v) => `<tr><td style="padding:4px 12px 4px 0;color:#666;vertical-align:top">${u(k)}</td><td style="padding:4px 0">${v}</td></tr>`;
    const html = `<div style="font-family:Arial,sans-serif;line-height:1.5"><h2 style="color:#b00020">Agent je izvedel nujno dejanje #${p.id}</h2>
      <p>Agent (Claude) je v <b>nujnem načinu</b> izvedel dejanje brez tvojega klika v panelu, s sklicem na tvojo pisno potrditev.</p>
      <table>${vr("Dejanje", u(kaj))}${vr("Cilj", u(cilj))}${vr("Prej → potem", vrstice.map(([k, a, b]) => `${u(k)}: ${u(a)} → <b>${u(b)}</b>`).join("<br>") || "—")}
      ${vr("Tvoja potrditev (citat)", `«${u(p.nujno_potrditev)}»`)}${vr("Seja", u(p.nujno_seja))}${vr("Čas", u(casBesedilo))}
      ${vr("Žeton agenta", u(`#${p.agent_zeton_id}${p.zeton_ime ? ` (${p.zeton_ime})` : ""}`))}</table>
      <p><b>Če te potrditve nisi napisal ti:</b> takoj prekliči žeton (panel → Agent) in preveri dejanje.</p>
      <p>Panel: <a href="${panel}">${panel}</a> (rdeč pas na vrhu ostane, dokler ne klikneš »Pregledal sem«).</p></div>`;
    return { zadeva, besedilo, html };
  }
  // VSAJ ENKRAT (menedzer 23. 10. 2026; razlika do I55): mail Martinu je glavno varovalo nujnega nacina (streznik citata ne more preveriti), zato je IZPAD hujsi od dvojnika
  // (dvojnik je nenevaren obvestilo Martinu, ne racun kupcu). Rezervacija UPDATE ... RETURNING (poskusi+1, prevzeto_at, izid_neznan = TRUE) pred klicem Resenda zaporedi
  // procese; poslano_at po uspehu. Vsak neuspeh (dokazana zavrnitev, rok, 5xx, prekinjena povezava, padec procesa med rezervacijo in klicem) se ponovi po NARASCAJOCEM
  // premoru (PREMOR * 2^(poskusi-1), vsaj rok Resenda + 1 s, da se poskus v teku ne podvoji), najvec NUJNO_MAIL_POSKUSOV; stara rezervacija brez poslano_at se prevzame znova.
  // Po izcrpanju: `[agent-nujno] POZOR` + Sentry error (najvec na 6 h) in rdece opozorilo v /admin/api/opozorila (admin_nadzor.js), dokler admin ne klikne »Pregledal sem«.
  const premorNajmanj = () => (Number(typeof dep.mailRokMs === "function" ? dep.mailRokMs() : dep.mailRokMs) || 15000) + 1000;   // rok Resenda je v index.js definiran kasneje
  const nujnoMailPogoj = `p.nujno_at IS NOT NULL AND p.nujno_mail_poslano_at IS NULL AND p.nujno_mail_poskusi < ${NUJNO_MAIL_POSKUSOV}
    AND (p.nujno_mail_prevzeto_at IS NULL OR p.nujno_mail_prevzeto_at < NOW() - (GREATEST($2::float8 * power(2, GREATEST(p.nujno_mail_poskusi - 1, 0)), $3::float8) * INTERVAL '1 millisecond'))`;
  const nujnoMailVTeku = new Set();
  // Klice ga SAMO nujna izvedba agenta (po odgovoru, brez await) in pospravljalec spodaj; nikoli nakup, webhook ali sken.
  async function nujnoMailPoslji(id) {
    if (nujnoMailVTeku.has(id)) return false;
    nujnoMailVTeku.add(id);
    try {
      const naslovi = prejemnikiNujno();
      if (!naslovi.length || !dep.imaResend()) { console.error(`[agent-nujno] POZOR: mail o nujnem dejanju ${id} ni mogoc (AGENT_NUJNO_MAIL ali Resend ni nastavljen); preveri panel`); return false; }
      const k = await pool.query(
        `UPDATE predlogi_dejanj p SET nujno_mail_poskusi = p.nujno_mail_poskusi + 1, nujno_mail_prevzeto_at = NOW(), nujno_mail_izid_neznan = TRUE
          WHERE p.id = $1 AND ${nujnoMailPogoj} RETURNING p.nujno_mail_poskusi`, [id, NUJNO_MAIL_PREMOR_MS, premorNajmanj()]);
      if (!k.rows.length) return false;   // ze poslan, v teku, v premoru ali izcrpan
      const poskus = k.rows[0].nujno_mail_poskusi;
      const p = (await pool.query(
        `SELECT p.id, p.dejanje, p.cilj_tip, p.cilj_id, p.spremembe, p.prej, p.nujno_potrditev, p.nujno_seja, p.nujno_at, p.agent_zeton_id, z.ime AS zeton_ime,
                CASE p.cilj_tip WHEN 'event' THEN (SELECT left(e.title, 200) FROM events e WHERE e.id = p.cilj_id)
                                WHEN 'club'  THEN (SELECT left(c.name, 200) FROM clubs c WHERE c.id = p.cilj_id) END AS cilj_naslov
           FROM predlogi_dejanj p JOIN agent_zetoni z ON z.id = p.agent_zeton_id WHERE p.id = $1`, [id])).rows[0];
      const m = nujnoMailVsebina(p);
      const r = await dep.posljiMail({ to: naslovi, subject: m.zadeva, html: m.html, text: m.besedilo });
      if (r && r.error) {
        const dokazana = dep.resendDokazanaZavrnitev(r.error);
        if (dokazana) await pool.query("UPDATE predlogi_dejanj SET nujno_mail_izid_neznan = FALSE WHERE id = $1 AND nujno_mail_poslano_at IS NULL", [id]);
        console.error(`[agent-nujno] mail o nujnem dejanju ${id} ni potrjen (poskus ${poskus}/${NUJNO_MAIL_POSKUSOV}, ${dokazana ? "zavrnjen" : "izid neznan"}: ${String(r.error.name || "")} ${String(r.error.message || "").slice(0, 100)}); ${poskus >= NUJNO_MAIL_POSKUSOV ? "poskusi izcrpani" : "ponovim po premoru"}`);
        if (poskus >= NUJNO_MAIL_POSKUSOV) izcrpanAlarm(true).catch(() => {});
        return false;
      }
      for (let i = 0; ; i++) {
        try { await pool.query("UPDATE predlogi_dejanj SET nujno_mail_poslano_at = NOW(), nujno_mail_izid_neznan = FALSE WHERE id = $1", [id]); break; }
        catch (e) { if (i >= 2) { console.error(`[agent-nujno] mail o nujnem dejanju ${id} je poslan, zapisa ni bilo mogoce narediti (${e && e.message}); morda pride se enkrat`); return true; } await new Promise((x) => setTimeout(x, 200)); }
      }
      console.log(`[agent-nujno] mail o nujnem dejanju ${id} poslan`);
      return true;
    } finally { nujnoMailVTeku.delete(id); }
  }
  // Alarm ob izcrpanih poskusih (nepregledano nujno dejanje brez poslanega maila): POZOR v dnevnik + Sentry ERROR, najvec enkrat na 6 h na proces (takoj = ob zadnjem poskusu).
  let zadnjiAlarm = 0;
  async function izcrpanAlarm(takoj = false) {
    if (!takoj && Date.now() - zadnjiAlarm < 6 * 3600 * 1000) return;
    const n = (await pool.query(`SELECT COUNT(*)::int AS n FROM predlogi_dejanj WHERE nujno_at IS NOT NULL AND nujno_pregledano_at IS NULL AND nujno_mail_poslano_at IS NULL
      AND nujno_mail_poskusi >= ${NUJNO_MAIL_POSKUSOV}`)).rows[0].n;
    if (!n || (takoj && Date.now() - zadnjiAlarm < 60000)) return;
    zadnjiAlarm = Date.now();
    const sporocilo = `[agent-nujno] POZOR: ${n} nujnih dejanj agenta brez poslanega maila Martinu (izcrpanih ${NUJNO_MAIL_POSKUSOV} poskusov); preveri Resend in panel (rdec pas, Opozorila)`;
    console.error(sporocilo);
    if (dep.javiNapako) dep.javiNapako(new Error(sporocilo));
  }
  // Pospravljalec: nujna dejanja zadnjih 7 dni brez poslanega maila. Lasten casovnik, ne na poti nakupa/skena.
  async function nujnoMailNeposlani() {
    if (!dep.imaResend() || !prejemnikiNujno().length) return;
    const r = await pool.query(`SELECT p.id FROM predlogi_dejanj p WHERE p.nujno_at > NOW() - INTERVAL '7 days' AND ${nujnoMailPogoj.replace("$2", "$1").replace("$3", "$2")} ORDER BY p.id LIMIT 10`,
      [NUJNO_MAIL_PREMOR_MS, premorNajmanj()]);
    for (const x of r.rows) await nujnoMailPoslji(x.id);
    await izcrpanAlarm();
  }
  const pospravljalec = setInterval(() => { nujnoMailNeposlani().catch((e) => console.error("[agent-nujno] pospravljalec:", e && e.message)); }, NUJNO_MAIL_PONOVI_MS);
  if (pospravljalec.unref) pospravljalec.unref();

  // --- panel: rdec pas (vsa nujna dejanja, ki jih admin se ni pregledal) in »Pregledal sem« ---
  adminRouter.get("/predlogi/nujno", async (req, res) => {
    const vse = req.query.vse === "1";
    try {
      const r = await pool.query(
        `SELECT p.id, p.dejanje, p.cilj_tip, p.cilj_id, p.spremembe, p.prej, p.razlog, p.nujno_potrditev, p.nujno_seja, p.nujno_at, p.nujno_pregledano_at,
                p.nujno_pregledal_admin_id, p.agent_zeton_id, z.ime AS zeton_ime,
                CASE WHEN p.nujno_mail_poslano_at IS NOT NULL THEN 'poslan' WHEN p.nujno_mail_poskusi >= ${NUJNO_MAIL_POSKUSOV} THEN 'ni_poslan'
                     WHEN p.nujno_mail_poskusi > 0 THEN 'ponavljam' ELSE 'caka' END AS mail, p.nujno_mail_poskusi AS mail_poskusi,
                CASE p.cilj_tip WHEN 'event' THEN (SELECT left(e.title, 200) FROM events e WHERE e.id = p.cilj_id)
                                WHEN 'club'  THEN (SELECT left(k.name, 200) FROM clubs k WHERE k.id = p.cilj_id) END AS cilj_naslov
           FROM predlogi_dejanj p JOIN agent_zetoni z ON z.id = p.agent_zeton_id
          WHERE p.nujno_at IS NOT NULL AND ($1::boolean OR p.nujno_pregledano_at IS NULL)
          ORDER BY p.nujno_at DESC LIMIT 100`, [vse]);
      const n = (await pool.query("SELECT COUNT(*)::int AS n FROM predlogi_dejanj WHERE nujno_at IS NOT NULL AND nujno_pregledano_at IS NULL")).rows[0].n;
      const dan = (await pool.query("SELECT COUNT(*)::int AS n FROM predlogi_dejanj WHERE nujno_at > NOW() - INTERVAL '24 hours'")).rows[0].n;
      res.set("Cache-Control", "no-store");
      return res.json({ nepregledanih: n, zadnjih_24h: dan, meja_24h: NUJNO_NA_24H, items: r.rows });
    } catch (e) { return dep.odgovoriNaNapako(res, e, "GET /admin/api/predlogi/nujno"); }
  });

  adminRouter.post("/predlogi/:id/nujno-pregledano", async (req, res) => {
    const id = celoId4(req.params.id);
    if (!id) return res.status(400).json({ error: "invalid_id", message: "Invalid proposal id." });
    const razlog = razlogAdmina(req.body);
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      const p = (await c.query("SELECT id, agent_zeton_id, nujno_at, nujno_pregledano_at FROM predlogi_dejanj WHERE id = $1 FOR UPDATE", [id])).rows[0];
      if (!p) { await c.query("ROLLBACK"); return res.status(404).json({ error: "not_found", message: "Proposal not found." }); }
      if (!p.nujno_at) { await c.query("ROLLBACK"); return res.status(409).json({ error: "ni_nujno", message: "This proposal was not run in emergency mode." }); }
      if (p.nujno_pregledano_at) { await c.query("ROLLBACK"); return res.status(409).json({ error: "ze_pregledano", message: "Already reviewed." }); }
      const v = (await c.query("UPDATE predlogi_dejanj SET nujno_pregledano_at = NOW(), nujno_pregledal_admin_id = $2 WHERE id = $1 RETURNING id, nujno_pregledano_at, nujno_pregledal_admin_id",
        [id, req.user.userId])).rows[0];
      await zapisiAdminDejanje(c, { user: req.user, predlog: { id, agentZetonId: p.agent_zeton_id } }, "agent.nujno_pregledano", "predlog", id,
        { nujno_pregledano_at: null }, { nujno_pregledano_at: v.nujno_pregledano_at.toISOString() }, razlog);
      await c.query("COMMIT");
      console.log(`Admin ${req.user.userId} pregledal nujno dejanje agenta (predlog ${id})`);
      return res.json({ predlog: v });
    } catch (e) {
      await c.query("ROLLBACK").catch(() => {});
      return dep.odgovoriNaNapako(res, e, "POST /admin/api/predlogi/:id/nujno-pregledano");
    } finally { c.release(); }
  });

  console.log(`[agent] predlogi: ${MEJA_NA_URO}/h na zeton, najvec ${CAKA_NAJVEC} cakajocih na zeton, rok 24 h; nujni nacin: ${(() => { const z = nujnoStikalo(); return z ? "IZKLOPLJEN (" + z.error + ")" : "vklopljen"; })()}, najvec ${NUJNO_NA_24H} na 24 h`);
  return { agentPoti, izvedi, DEJANJA, nujnoStikalo, nujnoMailPoslji };
}

module.exports = { ustvari, DEJANJA, nujnoIzkljuceno, NUJNO_IZKLJUCENO, NEVIDNI };
