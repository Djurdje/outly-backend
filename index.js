const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");
const { Resend } = require("resend");
const path = require("path");

const app = express();
// Render stoji za proxyjem. Brez tega je req.ip naslov proxyja in bi
// omejevanje veljalo za vse uporabnike skupaj.
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json());

// BIGINT (OID 20) pride iz pg kot niz ("1"); orders.id in tickets.id sta BIGSERIAL
// in aplikacija ju dekodira kot Int. Vrednosti so daleč pod 2^53, zato je varno.
const pgTipi = require("pg").types;
pgTipi.setTypeParser(20, (v) => (v === null ? null : parseInt(v, 10)));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false },
  // Varovalka: če zahtevek 10 s čaka na prosto povezavo (pool je zaseden ali se
  // je zaklenil), dobi napako in 500 namesto večnega čakanja. Brez tega bi en
  // hrošč tipa "pool.query med držanjem odjemalca" obesil cel strežnik.
  connectionTimeoutMillis: 10000,
});

// Resend init
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// ---------------------------
// Lastna prijava (bcrypt + HS256 JWT, verifikacijske kode, osveževalni žetoni)
// je bila odstranjena 11. 9. 2026: identiteta je Supabase Auth (glej spodaj).
// Tabele refresh_tokens, email_verification_codes in password_reset_codes
// ostanejo v bazi prazne/nedotaknjene do čistilne migracije.
// ---------------------------

// ---------------------------
// Omejevanje pogostosti (S-02)
// ---------------------------
// OMEJITEV: stevec je v pomnilniku procesa. Ob ponovnem zagonu se izprazni in
// ne deluje cez vec instanc. Za en Render proces zadosca; ko bo instanc vec,
// to zamenja Redis ali tabela v bazi. Racun je poleg tega zascisten se z
// zaklepom v tabeli users, ki NI odvisen od IP naslova.
const stevci = new Map();

setInterval(() => {
  const zdaj = Date.now();
  for (const [k, v] of stevci) if (v.doKdaj <= zdaj) stevci.delete(k);
}, 60 * 1000).unref();

function omeji({ kljuc, najvec, oknoSekund }) {
  return (req, res, next) => {
    const id = `${kljuc}:${req.ip}`;
    const zdaj = Date.now();
    const v = stevci.get(id);

    if (!v || v.doKdaj <= zdaj) {
      stevci.set(id, { n: 1, doKdaj: zdaj + oknoSekund * 1000 });
      return next();
    }

    v.n += 1;
    if (v.n > najvec) {
      const cezKoliko = Math.ceil((v.doKdaj - zdaj) / 1000);
      res.set("Retry-After", String(cezKoliko));
      return res.status(429).send("Too many requests. Please try again later.");
    }
    next();
  };
}

// ---------------------------
// Supabase Auth (migracija 010) — edina identiteta aplikacije in spletne strani
// ---------------------------
// Supabase izda ES256 JWT; javni ključ je na /auth/v1/.well-known/jwks.json.
// Preverjamo ga sami z vgrajenim crypto (brez nove odvisnosti): podpis JWT
// pri ES256 je surov r||s (IEEE P1363), ne DER.
// SUPABASE_URL in objavljeni ključ (sb_publishable_…) sta JAVNA podatka — ista
// sta v supabase-config.js na outly.si. Skrivnosti (service_role) tu NI in
// je ne sme biti.
const SUPABASE_URL = (process.env.SUPABASE_URL || "https://zbewqcxnvrwebxonvebx.supabase.co").replace(/\/+$/, "");
const SUPABASE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY || "sb_publishable_NzgXZhG7RGs0mZMjGYtyig_XfOvepXS";
const SUPABASE_ISS = SUPABASE_URL + "/auth/v1";

const jwks = { kljuci: new Map(), nalozeno: 0 };
const JWKS_OSVEZI_MS = 10 * 60 * 1000;

async function naloziJwks(prisilno) {
  const zdaj = Date.now();
  if (!prisilno && jwks.kljuci.size && zdaj - jwks.nalozeno < JWKS_OSVEZI_MS) return;
  // Vrtenje ključa je redko; brez tega bi neveljaven žeton z izmišljenim kid
  // sprožil klic na Supabase ob vsakem poskusu.
  if (prisilno && zdaj - jwks.nalozeno < 60 * 1000) return;
  let novi;
  try {
    const r = await fetch(SUPABASE_ISS + "/.well-known/jwks.json", { signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const telo = await r.json();
    novi = new Map();
    for (const k of telo.keys || []) {
      if (k.kty !== "EC" || k.crv !== "P-256" || !k.kid) continue;
      novi.set(k.kid, crypto.createPublicKey({ key: k, format: "jwk" }));
    }
    if (!novi.size) throw new Error("empty");
  } catch (e) {
    // Supabase nedosegljiv: stari ključi ostanejo v uporabi (vrtenje je redko),
    // brez ključev pa klicatelj dobi 503, ne 401 (401 bi aplikacijo odjavil).
    if (jwks.kljuci.size) { jwks.nalozeno = zdaj - JWKS_OSVEZI_MS + 60 * 1000; return; }
    const n = new Error("JWKS " + (e && e.message)); n.jwks = true; throw n;
  }
  jwks.kljuci = novi;
  jwks.nalozeno = zdaj;
}

function b64urlJson(del) {
  return JSON.parse(Buffer.from(del, "base64url").toString("utf8"));
}

// Vrne payload ali vrže napako. Preveri: obliko, alg ES256, kid, podpis,
// izdajatelja, občinstvo 'authenticated', exp/nbf.
async function preveriSupabaseZeton(token) {
  const deli = token.split(".");
  if (deli.length !== 3) throw new Error("oblika");
  const glava = b64urlJson(deli[0]);
  if (glava.alg !== "ES256" || !glava.kid) throw new Error("alg");

  await naloziJwks(false);
  let kljuc = jwks.kljuci.get(glava.kid);
  if (!kljuc) { await naloziJwks(true); kljuc = jwks.kljuci.get(glava.kid); }
  if (!kljuc) throw new Error("kid");

  let ok = false;
  try {
    ok = crypto.verify(
      "sha256",
      Buffer.from(deli[0] + "." + deli[1]),
      { key: kljuc, dsaEncoding: "ieee-p1363" },
      Buffer.from(deli[2], "base64url")
    );
  } catch (_) { ok = false; }
  if (!ok) throw new Error("podpis");

  const p = b64urlJson(deli[1]);
  const zdaj = Math.floor(Date.now() / 1000);
  if (p.iss !== SUPABASE_ISS) throw new Error("iss");
  const aud = Array.isArray(p.aud) ? p.aud : [p.aud];
  if (!aud.includes("authenticated")) throw new Error("aud");
  if (typeof p.exp !== "number" || p.exp <= zdaj) throw new Error("exp");
  if (typeof p.nbf === "number" && p.nbf > zdaj + 60) throw new Error("nbf");
  if (typeof p.sub !== "string" || !/^[0-9a-f-]{36}$/i.test(p.sub)) throw new Error("sub");
  if (typeof p.email !== "string" || !p.email.includes("@")) throw new Error("email");
  if (p.is_anonymous === true) throw new Error("anon");
  return p;
}

// Računi, izbrisani v tej instanci (DELETE /me): Supabasov žeton je brez stanja
// in velja še do ure, zato bi ga ponovljen klic (npr. GET /me v aplikaciji)
// sicer obudil kot prazen nov račun. Ključ = sub, vrednost = exp žetona.
const izbrisaniSub = new Map();
setInterval(() => {
  const zdaj = Math.floor(Date.now() / 1000);
  for (const [k, exp] of izbrisaniSub) if (exp <= zdaj) izbrisaniSub.delete(k);
}, 5 * 60 * 1000).unref();

const POLJA_SEJE = "id, email, username, role";

// Uporabniško ime za novo vrstico: iz user_metadata.username (aplikacija ga
// pošlje ob registraciji), sicer iz dela e-naslova pred @. Pravila kot pri
// PATCH /me: 3–20 znakov, črke/številke/podčrtaj.
function predlogImena(p) {
  const meta = p.user_metadata || {};
  const zeljeno = typeof meta.username === "string" ? meta.username.trim() : "";
  if (/^[a-zA-Z0-9_]{3,20}$/.test(zeljeno)) return zeljeno;
  const osnova = String(p.email).split("@")[0].replace(/[^a-zA-Z0-9_]/g, "").slice(0, 16);
  return (osnova.length >= 3 ? osnova : "user") ;
}

// Lokalna vrstica za Supabasov račun:
//   1. po supabase_uid,
//   2. po e-naslovu (obstoječi račun iz časov lastne prijave → poveže se; Supabase
//      e-naslov potrdi pred izdajo seje, zato je lastništvo naslova dokazano),
//   3. sicer nova vrstica (email_verified = true, brez gesla).
async function uporabnikIzSupabase(p) {
  const uid = p.sub.toLowerCase();
  const email = String(p.email).trim().toLowerCase();

  if (izbrisaniSub.has(uid)) throw new Error("izbrisan");

  const r1 = await pool.query(`SELECT ${POLJA_SEJE} FROM users WHERE supabase_uid=$1`, [uid]);
  if (r1.rows.length) return r1.rows[0];

  // Povezava po e-naslovu in nov račun samo s POTRJENIM e-naslovom. Supabase
  // ga s "Confirm email" potrdi pred prvo sejo in to zapiše v user_metadata;
  // če bi kdo to nastavitev izklopil, bi sicer vsak lahko prevzel tuj stari
  // račun z vpisom tujega e-naslova.
  if (!(p.user_metadata && p.user_metadata.email_verified === true)) throw new Error("email_unverified");

  const r2 = await pool.query(
    `UPDATE users SET supabase_uid=$1, email_verified=true, failed_login_count=0, locked_until=NULL
     WHERE email=$2 AND supabase_uid IS NULL RETURNING ${POLJA_SEJE}`,
    [uid, email]
  );
  if (r2.rows.length) return r2.rows[0];

  const ime = predlogImena(p);
  for (let poskus = 0; poskus < 4; poskus++) {
    const kandidat = poskus === 0 ? ime : `${ime.slice(0, 14)}_${crypto.randomInt(1000, 9999)}`;
    try {
      const r3 = await pool.query(
        `INSERT INTO users (email, password_hash, username, email_verified, supabase_uid)
         VALUES ($1, NULL, $2, true, $3) RETURNING ${POLJA_SEJE}`,
        [email, kandidat, uid]
      );
      return r3.rows[0];
    } catch (e) {
      if (e && e.code === "23505") {
        // Isto ime že obstaja → nov poskus s pripono. Isti e-naslov ali uid
        // (tekma dveh prvih klicev) → poišči še enkrat.
        const c = String(e.constraint || "");
        if (c.includes("supabase")) {
          const r4 = await pool.query(`SELECT ${POLJA_SEJE} FROM users WHERE supabase_uid=$1`, [uid]);
          if (r4.rows.length) return r4.rows[0];
        }
        if (c.includes("email")) {
          // Vrstica s tem e-naslovom že kaže na drug (star) Supabasov uid —
          // isti lastnik naslova se je pri Supabase registriral znova.
          const r4 = await pool.query(
            `UPDATE users SET supabase_uid=$1 WHERE email=$2 RETURNING ${POLJA_SEJE}`, [uid, email]
          );
          if (r4.rows.length) return r4.rows[0];
        }
        continue;
      }
      throw e;
    }
  }
  throw new Error("username");
}

// ---------------------------
// Auth middleware
// ---------------------------
// Sprejme samo Supabasov žeton (ES256). req.user = { userId, email, username,
// role, auth: 'supabase', supabaseToken, supabaseSub, supabaseExp }. Vloga pride
// iz baze ob vsakem klicu (ni v žetonu), zato sprememba vloge velja takoj.
async function razberiUporabnika(token) {
  const p = await preveriSupabaseZeton(token);
  const u = await uporabnikIzSupabase(p);
  return { userId: u.id, email: u.email, username: u.username, role: u.role, auth: "supabase",
           supabaseToken: token, supabaseSub: p.sub.toLowerCase(), supabaseExp: p.exp };
}

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).send("Missing token.");
  try {
    req.user = await razberiUporabnika(token);
    return next();
  } catch (err) {
    if (err && err.jwks) {
      console.error(err.message);
      return res.status(503).send("Auth service unavailable.");
    }
    if (err && err.message === "email_unverified") return res.status(403).send("Email not verified.");
    if (err && err.code) { console.error(err); return res.status(500).send("Server error."); }
    return res.status(401).send("Invalid token.");
  }
}

// ---------------------------
// Role middleware
// ---------------------------
function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).send("Unauthorized.");
    if (!allowed.includes(req.user.role)) return res.status(403).send("Forbidden.");
    next();
  };
}

// ---------------------------
// Klub uporabnika in vloga v njem (migracija 009)
// ---------------------------
// Lastnik: clubs.owner_user_id -> 'owner'. Član ekipe: club_members ->
// 'manager' ali 'doorman'. Vsak uporabnik ima največ en klub.
// Vrne null, če uporabnik nima kluba.
async function klubUporabnika(userId) {
  const l = await pool.query("SELECT id FROM clubs WHERE owner_user_id=$1 LIMIT 1", [userId]);
  if (l.rows.length) return { clubId: l.rows[0].id, role: "owner" };
  const m = await pool.query("SELECT club_id, role FROM club_members WHERE user_id=$1 LIMIT 1", [userId]);
  if (m.rows.length) return { clubId: m.rows[0].club_id, role: m.rows[0].role };
  return null;
}

// Middleware za poslovne poti: req.klub = { clubId, role }.
// Brez argumentov spusti vsako vlogo v klubu; z argumenti samo naštete.
// Admin brez lastnega kluba dobi { clubId: null, role: 'admin' } — poti, ki
// rabijo klub, mu vrnejo 404 kot do zdaj; poti za urejanje dogodkov ga spustijo.
// Vratar (doorman) sme SAMO skenirati in gledati vstopnice dogodka.
function requireClub(...vloge) {
  return async (req, res, next) => {
    try {
      if (!req.user) return res.status(401).send("Unauthorized.");
      let k = await klubUporabnika(req.user.userId);
      if (!k) {
        if (req.user.role === "admin") k = { clubId: null, role: "admin" };
        else if (req.user.role === "business") return res.status(404).send("Club not found.");
        else return res.status(403).send("Forbidden.");
      }
      if (vloge.length && k.role !== "admin" && !vloge.includes(k.role)) {
        return res.status(403).send("Your role in the club does not allow this.");
      }
      req.klub = k;
      next();
    } catch (e) {
      console.error(e);
      return res.status(500).send("Server error.");
    }
  };
}

// test endpoint
app.get("/", (req, res) => {
  res.send("Outly backend OK");
});

// Admin panel: statična stran v mapi admin/ (en HTML + JS, brez ogrodja).
// Sama stran ne razkrije ničesar — vsi podatki pridejo prek poti /admin/api/*,
// ki zahtevajo vlogo admin.
app.use("/admin", express.static(path.join(__dirname, "admin"), { index: "index.html" }));

// ---------------------------
// ME (protected)
// ---------------------------
app.get("/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ${POLJA_UPORABNIKA} FROM users WHERE id=$1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) return res.status(404).send("User not found.");
    // Klub in vloga v njem (lastnik ali član ekipe, migracija 009). Aplikacija
    // po club_role pokaže poslovni obraz — tudi vratarju, ki ima users.role 'user'.
    const k = await klubUporabnika(req.user.userId);
    // Čakajoča vabila v ekipo (migracija 013) — značka na zvoncu v "My clubs".
    const v = await pool.query("SELECT COUNT(*)::int AS n FROM club_invites WHERE user_id=$1 AND status='pending'", [req.user.userId]);
    // Čakajoče prošnje za prijateljstvo (migracija 016) — obvestila v aplikaciji.
    const pf = await pool.query("SELECT COUNT(*)::int AS n FROM friend_requests WHERE to_user_id=$1 AND status='pending'", [req.user.userId]);
    return res.status(200).json({
      ...result.rows[0],
      club_id: k ? k.clubId : null,
      club_role: k ? k.role : null,
      pending_invites: v.rows[0] ? v.rows[0].n : 0,
      pending_friend_requests: pf.rows[0] ? pf.rows[0].n : 0,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// PATCH /me/avatar (protected)
// ---------------------------
// Aplikacija to pot klice od zacetka, backend je ni imel -> vsako shranjevanje
// profilne slike je vracalo 404. Popravek najdbe P-02.
app.patch("/me/avatar", requireAuth, async (req, res) => {
  try {
    const avatarUrl = req.body.avatarUrl ?? req.body.avatar_url;

    if (typeof avatarUrl !== "string" || !avatarUrl.trim()) {
      return res.status(400).send("Missing avatarUrl.");
    }

    // Sprejmemo samo naslove iz NASEGA Cloudinaryja. Brez tega bi lahko
    // kdorkoli za svojo profilno sliko nastavil poljuben tuj URL in ga
    // servirali vsem uporabnikom (sledenje, phishing, neprimerna vsebina).
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    if (!cloudName) return res.status(500).send("Cloudinary env vars not set.");

    const dovoljenaPredpona = `https://res.cloudinary.com/${cloudName}/`;
    if (!avatarUrl.startsWith(dovoljenaPredpona)) {
      return res.status(400).send("avatarUrl must be a Cloudinary URL from this account.");
    }
    if (avatarUrl.length > 500) {
      return res.status(400).send("avatarUrl too long.");
    }

    const r = await pool.query(
      `UPDATE users SET avatar_url=$1 WHERE id=$2
       RETURNING id, email, username, role, avatar_url, email_verified, created_at`,
      [avatarUrl, req.user.userId]
    );

    if (r.rows.length === 0) return res.status(404).send("User not found.");
    return res.status(200).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// PROFIL: dokoncanje racuna (zaslona "complete acc" in "complete acc 2")
// ---------------------------

// 21 zanrov iz Figme. Seznam je zaprt namenoma: brez tega bi v bazo priseli
// poljubni nizi in "Suggestions" ne bi imel po cem grupirati.
const ZANRI = [
  "electronic","hiphop","pop","rnb","rock","metal","punk","afrobeat","balkan",
  "latino","country","hardcore","70s","80s","90s","rap","2000s","house",
  "garage","trap","techno"
];

app.get("/genres", (req, res) => res.status(200).json({ genres: ZANRI }));

// Polja, ki jih vrnemo o uporabniku. Na enem mestu, da se GET /me, PATCH /me
// in PATCH /me/avatar ne razidejo.
const POLJA_UPORABNIKA = `id, email, username, role, avatar_url, email_verified,
  phone, phone_verified, date_of_birth, country, genres, onboarded_at, created_at,
  share_plans_with_friends`;

app.patch("/me", requireAuth, async (req, res) => {
  try {
    const b = req.body || {};
    const sets = [];
    const vrednosti = [];
    const dodaj = (stolpec, vrednost) => {
      vrednosti.push(vrednost);
      sets.push(`${stolpec} = $${vrednosti.length}`);
    };

    // --- uporabnisko ime ---
    if (b.username !== undefined) {
      const ime = String(b.username).trim();
      if (ime.length < 3)  return res.status(400).send("Username too short.");
      if (ime.length > 20) return res.status(400).send("Username too long.");
      if (!/^[a-zA-Z0-9_]+$/.test(ime)) {
        return res.status(400).send("Username invalid. Use letters, numbers, underscore.");
      }
      // Primerjava brez upostevanja velikosti crk: "Martin" in "martin" sta
      // isto ime. Registracija tega doslej ni preverjala.
      const zasedeno = await pool.query(
        "SELECT id FROM users WHERE LOWER(username)=LOWER($1) AND id<>$2", [ime, req.user.userId]
      );
      if (zasedeno.rows.length > 0) return res.status(409).send("Username already in use.");
      dodaj("username", ime);
    }

    // --- telefonska stevilka ---
    if (b.phone !== undefined) {
      if (b.phone === null || b.phone === "") {
        dodaj("phone", null);
        dodaj("phone_verified", false);
      } else {
        const tel = String(b.phone).replace(/[\s\-()]/g, "");
        if (!/^\+[1-9][0-9]{7,14}$/.test(tel)) {
          return res.status(400).send("Phone must be in E.164 format, e.g. +38641123456.");
        }
        const zasedena = await pool.query(
          "SELECT id FROM users WHERE phone=$1 AND id<>$2", [tel, req.user.userId]
        );
        if (zasedena.rows.length > 0) return res.status(409).send("Phone number already in use.");
        dodaj("phone", tel);
        // Vsaka sprememba stevilke razveljavi prejsnjo potrditev.
        dodaj("phone_verified", false);
      }
    }

    // --- datum rojstva ---
    if (b.dateOfBirth !== undefined || b.date_of_birth !== undefined) {
      const d = b.dateOfBirth ?? b.date_of_birth;
      if (d === null || d === "") {
        dodaj("date_of_birth", null);
      } else {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(String(d))) {
          return res.status(400).send("dateOfBirth must be YYYY-MM-DD.");
        }
        const dat = new Date(d + "T00:00:00Z");
        if (Number.isNaN(dat.getTime())) return res.status(400).send("Invalid dateOfBirth.");
        const let_ = (Date.now() - dat.getTime()) / (365.2425 * 24 * 3600 * 1000);
        if (let_ <= 0)  return res.status(400).send("dateOfBirth cannot be in the future.");
        if (let_ > 120) return res.status(400).send("dateOfBirth is not plausible.");
        // Meja za veljavno privolitev otroka v Sloveniji je 15 let (ZVOP-2, 8. clen).
        // Aplikacija to preveri ze pred posiljanjem; streznik je zadnja obramba.
        if (let_ < 15)  return res.status(400).send("You must be at least 15 years old.");
        dodaj("date_of_birth", d);
      }
    }

    // --- drzava ---
    if (b.country !== undefined) {
      if (b.country === null || b.country === "") {
        dodaj("country", null);
      } else {
        const dr = String(b.country).trim().toUpperCase();
        if (!/^[A-Z]{2}$/.test(dr)) return res.status(400).send("country must be a 2-letter ISO code, e.g. SI.");
        dodaj("country", dr);
      }
    }

    // --- zanri ---
    if (b.genres !== undefined) {
      if (!Array.isArray(b.genres)) return res.status(400).send("genres must be an array.");
      if (b.genres.length > ZANRI.length) return res.status(400).send("Too many genres.");
      const izbrani = [...new Set(b.genres.map(g => String(g).trim().toLowerCase()))];
      const neznani = izbrani.filter(g => !ZANRI.includes(g));
      if (neznani.length > 0) {
        return res.status(400).json({ error: "unknown_genres", unknown: neznani, allowed: ZANRI });
      }
      dodaj("genres", izbrani);
    }

    // --- prijatelji vidijo moje nacrte (migracija 016) ---
    if (b.share_plans_with_friends !== undefined || b.sharePlansWithFriends !== undefined) {
      const v = b.share_plans_with_friends ?? b.sharePlansWithFriends;
      if (typeof v !== "boolean") return res.status(400).send("share_plans_with_friends must be true or false.");
      dodaj("share_plans_with_friends", v);
    }

    if (sets.length === 0) return res.status(400).send("Nothing to update.");

    // Racun velja za dokoncan, ko ima datum rojstva in vsaj en zanr.
    sets.push(`onboarded_at = CASE
        WHEN onboarded_at IS NOT NULL THEN onboarded_at
        WHEN date_of_birth IS NOT NULL AND COALESCE(array_length(genres,1),0) > 0 THEN NOW()
        ELSE NULL END`);

    vrednosti.push(req.user.userId);
    const r = await pool.query(
      `UPDATE users SET ${sets.join(", ")} WHERE id = $${vrednosti.length}
       RETURNING ${POLJA_UPORABNIKA}`,
      vrednosti
    );

    if (r.rows.length === 0) return res.status(404).send("User not found.");

    // Drugi prehod, da onboarded_at upostevа vrednosti, ki so bile pravkar vpisane.
    const r2 = await pool.query(
      `UPDATE users SET onboarded_at = NOW()
       WHERE id=$1 AND onboarded_at IS NULL
         AND date_of_birth IS NOT NULL AND COALESCE(array_length(genres,1),0) > 0
       RETURNING ${POLJA_UPORABNIKA}`,
      [req.user.userId]
    );

    return res.status(200).json(r2.rows[0] || r.rows[0]);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// BRISANJE RAČUNA (Apple 5.1.1(v), najdba A-01)
// ---------------------------
// Apple od junija 2022 zahteva, da uporabnik racun izbrise ZNOTRAJ aplikacije.
// Brez tega je oddaja zavrnjena.
// Supabasov račun: geslo je preverila aplikacija tik pred klicem (ponovna
// prijava pri Supabase), mi ga nimamo. Po izbrisu lokalnih podatkov pokličemo
// še Supabasov RPC delete_my_account (shema 10 spletne strani) Z UPORABNIKOVIM
// žetonom — izbriše auth.users vrstico in prijavo na waitlisti. Brez tega bi
// se ob naslednji prijavi ustvaril prazen lokalni račun.
async function izbrisiSupabaseRacun(token) {
  const r = await fetch(SUPABASE_URL + "/rest/v1/rpc/delete_my_account", {
    method: "POST",
    headers: { apikey: SUPABASE_KEY, Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: "{}",
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) throw new Error("delete_my_account " + r.status + " " + (await r.text()).slice(0, 200));
}

app.delete("/me", requireAuth, omeji({ kljuc: "delete", najvec: 5, oknoSekund: 3600 }), async (req, res) => {
  try {
    const { password } = req.body || {};
    const supabase = true;

    if (typeof password !== "string" || !password) {
      return res.status(400).send("Password required to delete account.");
    }

    {
      // Ponovna prijava pri Supabase s trenutnim geslom: ukraden žeton (velja
      // do ure) sam ne sme zadostovati za nepovraten izbris.
      const r = await fetch(SUPABASE_ISS + "/token?grant_type=password", {
        method: "POST",
        headers: { apikey: SUPABASE_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({ email: req.user.email, password }),
        signal: AbortSignal.timeout(8000),
      }).catch(() => null);
      if (!r) return res.status(503).send("Auth service unavailable.");
      if (r.status === 400 || r.status === 401 || r.status === 403) return res.status(401).send("Invalid credentials.");
      if (!r.ok) return res.status(503).send("Auth service unavailable.");
    }

    // Brez tabele orders (pred migracijo 002) je izbris preprost.
    if (!obstajajoNarocila) {
      if (supabase) { await izbrisiSupabaseRacun(req.user.supabaseToken); izbrisaniSub.set(req.user.supabaseSub, req.user.supabaseExp); }
      await pool.query("DELETE FROM users WHERE id=$1", [req.user.userId]);
      return res.status(200).json({ message: "Account deleted." });
    }

    // Od migracije 002 naprej sta v igri dve nasprotujoci si zahtevi:
    // Apple hoce, da uporabnik racun izbrise; davcni predpisi hocejo, da se
    // racun o nakupu ohrani. Resitev je anonimizacija, ne izbris naracil.
    const odjemalec = await pool.connect();
    try {
      await odjemalec.query("BEGIN");

      // 1. Lastnik kluba, ki ima narocila, racuna ne more izbrisati — klub
      //    mora najprej dobiti drugega lastnika. Baza bi to zavrnila tako ali
      //    tako, a s tem uporabnik dobi razumljivo sporocilo namesto napake 500.
      const klubi = await odjemalec.query(
        `SELECT c.id, c.name, COUNT(o.id) AS narocil
         FROM clubs c LEFT JOIN orders o ON o.club_id = c.id
         WHERE c.owner_user_id = $1
         GROUP BY c.id, c.name
         HAVING COUNT(o.id) > 0`,
        [req.user.userId]
      );

      if (klubi.rows.length > 0) {
        await odjemalec.query("ROLLBACK");
        return res.status(409).json({
          error: "club_has_orders",
          message: "Your club has sold tickets. Transfer club ownership before deleting your account.",
          clubs: klubi.rows.map(k => ({ id: k.id, name: k.name, orders: Number(k.narocil) })),
        });
      }

      // 2. Osebni podatki na naracilih se odvezejo. Znesek, datum in dogodek
      //    ostanejo, ker so racunovodski podatek; e-naslov ni.
      await odjemalec.query(
        `UPDATE orders
         SET buyer_email = 'izbrisan-' || id || '@outly.invalid'
         WHERE user_id = $1`,
        [req.user.userId]
      );

      // 3. Izbris uporabnika. orders.user_id je ON DELETE SET NULL, zato
      //    naracila ostanejo, a niso vec vezana na osebo.
      await odjemalec.query("DELETE FROM users WHERE id=$1", [req.user.userId]);

      // 4. Supabasov račun — PRED potrditvijo transakcije: če Supabase odpove,
      //    ostane vse, kot je bilo, in uporabnik lahko poskusi znova.
      if (supabase) {
        try { await izbrisiSupabaseRacun(req.user.supabaseToken); }
        catch (e) {
          await odjemalec.query("ROLLBACK");
          console.error(e);
          return res.status(502).send("Could not delete the account at the identity provider. Please try again.");
        }
      }

      await odjemalec.query("COMMIT");
      if (supabase) izbrisaniSub.set(req.user.supabaseSub, req.user.supabaseExp);
      return res.status(200).json({ message: "Account deleted." });
    } catch (e) {
      await odjemalec.query("ROLLBACK").catch(() => {});
      throw e;
    } finally {
      odjemalec.release();
    }
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// CLUBS (public + business create)
// ---------------------------
// Stolpci, ki smejo ven javno. NAMENOMA ni "SELECT *": migracija 002 je
// klubom dodala stripe_account_id, ki z zvezdico ni bil viden nikomur v
// pregledu, javno pa bi ga vrnil vsak klic /clubs. Vsak nov stolpec je
// treba tu dodati zavestno.
const JAVNI_STOLPCI_KLUBA = `id, owner_user_id, name, logo_url, banner_url, description,
  contact_email, contact_phone, instagram, website, address, city, country,
  lat, lng, min_age, genres, created_at, bar_prices, gallery_urls, video_url`;

// Cenik bara (migracija 014): seznam postavk, ki ga klub ureja v celoti.
// Vrne ocisceno kopijo ali niz z napako. Cene v centih, kot pri vstopnicah.
const CENIK_NAJVEC_POSTAVK = 60;
function preveriCenik(vhod) {
  if (!Array.isArray(vhod)) return { napaka: "barPrices must be an array." };
  if (vhod.length > CENIK_NAJVEC_POSTAVK) return { napaka: `barPrices: at most ${CENIK_NAJVEC_POSTAVK} items.` };
  const postavke = [];
  for (const p of vhod) {
    if (!p || typeof p !== "object" || Array.isArray(p)) return { napaka: "barPrices: each item must be an object." };
    const name = String(p.name ?? "").trim();
    if (name.length < 1 || name.length > 60) return { napaka: "barPrices: name must be 1-60 characters." };
    const cents = p.price_cents ?? p.priceCents;
    if (!Number.isInteger(cents) || cents < 0 || cents > 100000) {
      return { napaka: "barPrices: price_cents must be an integer between 0 and 100000." };
    }
    const category = String(p.category ?? "").trim().slice(0, 30);
    const postavka = { name, price_cents: cents };
    if (category) postavka.category = category;
    postavke.push(postavka);
  }
  return { postavke };
}

// Lastnik vidi še stanje vidnosti in Stripa, ne pa stripe_account_id.
const STOLPCI_KLUBA_LASTNIKA = `${JAVNI_STOLPCI_KLUBA}, hidden, stripe_charges_enabled, stripe_payouts_enabled`;

function stevilo(vrednost, privzeto, najvec) {
  const n = parseInt(vrednost, 10);
  if (Number.isNaN(n) || n < 0) return privzeto;
  return Math.min(n, najvec);
}
app.get("/clubs", async (req, res) => {
  try {
    const limit  = stevilo(req.query.limit, 100, 200);
    const offset = stevilo(req.query.offset, 0, 100000);

    const pogoji = [];
    const p = [];

    if (req.query.city) { p.push(req.query.city); pogoji.push(`city ILIKE $${p.length}`); }
    if (req.query.q) {
      p.push(`%${String(req.query.q).trim()}%`);
      pogoji.push(`(name ILIKE $${p.length} OR city ILIKE $${p.length} OR description ILIKE $${p.length})`);
    }
    // Zemljevid potrebuje samo klube s koordinatami.
    if (req.query.withCoords === "true") pogoji.push("lat IS NOT NULL AND lng IS NOT NULL");
    // Skriti klubi (admin panel, migracija 006) javno ne obstajajo.
    pogoji.push("hidden = FALSE");

    const kje = pogoji.length ? "WHERE " + pogoji.join(" AND ") : "";

    const skupaj = await pool.query(`SELECT COUNT(*)::int AS n FROM clubs ${kje}`, p);

    p.push(limit); p.push(offset);
    const r = await pool.query(
      `SELECT ${JAVNI_STOLPCI_KLUBA} FROM clubs ${kje}
       ORDER BY created_at DESC LIMIT $${p.length - 1} OFFSET $${p.length}`,
      p
    );

    // Skupno stevilo v glavi, da telo ostane navaden seznam in se aplikaciji
    // ni treba spreminjati. Dekoder v Swiftu pricakuje [APIClub].
    res.set("X-Total-Count", String(skupaj.rows[0].n));
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// Lahek seznam za zemljevid. MapView je doslej risal EN sam klub, ker je
// izbiral najblizjega; poleg tega je /clubs vracal celotne zapise s polnimi
// opisi. Ta pot vrne samo to, kar pin potrebuje.
app.get("/clubs/map", async (req, res) => {
  try {
    const p = [];
    const pogoji = ["lat IS NOT NULL", "lng IS NOT NULL", "hidden = FALSE"];

    // Neobvezni okvir zemljevida: minLat,minLng,maxLat,maxLng
    const b = req.query.bbox;
    if (b) {
      const d = String(b).split(",").map(Number);
      if (d.length !== 4 || d.some(Number.isNaN)) {
        return res.status(400).send("bbox must be minLat,minLng,maxLat,maxLng.");
      }
      p.push(d[0], d[2], d[1], d[3]);
      pogoji.push("lat BETWEEN $1 AND $2", "lng BETWEEN $3 AND $4");
    }

    const r = await pool.query(
      `SELECT id, name, lat, lng, logo_url, city, min_age, genres
       FROM clubs WHERE ${pogoji.join(" AND ")} ORDER BY id LIMIT 1000`,
      p
    );
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

app.get("/clubs/:id", async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).send("Invalid club id.");
    const r = await pool.query(
      `SELECT ${JAVNI_STOLPCI_KLUBA} FROM clubs WHERE id=$1 AND hidden = FALSE`, [req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).send("Club not found.");
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

app.post("/clubs", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const {
      name,
      logoUrl,
      bannerUrl,
      description,
      contactEmail,
      contactPhone,
      instagram,
      website,
      address,
      city,
      country,
      lat,
      lng,
      minAge,
      genres
    } = req.body;

    if (!name) return res.status(400).send("Missing name.");

    const r = await pool.query(
      `INSERT INTO clubs
      (owner_user_id, name, logo_url, banner_url, description,
       contact_email, contact_phone, instagram, website,
       address, city, country, lat, lng, min_age, genres)
       VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       RETURNING ${STOLPCI_KLUBA_LASTNIKA}`,
      [
        req.user.userId,
        name,
        logoUrl || "",
        bannerUrl || "",
        description || "",
        contactEmail || "",
        contactPhone || "",
        instagram || "",
        website || "",
        address || "",
        city || "",
        country || "",
        lat ?? null,
        lng ?? null,
        minAge ?? 18,
        Array.isArray(genres) ? genres : []
      ]
    );

    res.status(201).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// ---------------------------
// Cloudinary signature (protected)
// ---------------------------
function cloudinarySignature(paramsToSign, apiSecret) {
  // Cloudinary: sort params by key, join key=value with &, append api_secret, sha1
  const sortedKeys = Object.keys(paramsToSign).sort();
  const toSign = sortedKeys
    .map((k) => `${k}=${paramsToSign[k]}`)
    .join("&") + apiSecret;

  return crypto.createHash("sha1").update(toSign).digest("hex");
}

// Skupna logika za obe poti.
// Poleg timestamp in folder podpisemo tudi public_id, vezan na uporabnika.
// Ker je public_id del podpisa, ga odjemalec ne more zamenjati -> nihce ne more
// pisati cez tuje slike. Popravek najdbe S-04.
async function izdajPodpis(req, res) {
  try {
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(500).send("Cloudinary env vars not set.");
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const folder = process.env.CLOUDINARY_FOLDER || "outly";

    // npr. outly/u42/1757193600-3f9a1c2b
    const publicId = `${folder}/u${req.user.userId}/${timestamp}-${crypto.randomBytes(4).toString("hex")}`;

    const paramsToSign = { folder, public_id: publicId, timestamp };
    const signature = cloudinarySignature(paramsToSign, apiSecret);

    return res.status(200).json({
      timestamp,
      signature,
      apiKey,
      cloudName,
      folder,
      publicId
    });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
}

// Kanonicna pot. Aplikacija je od zacetka klicala prav to, backend pa je
// streg samo GET /cloudinary/signature -> nalaganje slik je vracalo 404.
// Popravek najdbe P-01.
app.post("/uploads/cloudinary-signature", requireAuth, izdajPodpis);

// Stara pot. Ohranjena, da nic ne odpove med prehodom. Odstrani jo, ko bo
// v obtoku samo se nova razlicica aplikacije.
app.get("/cloudinary/signature", requireAuth, izdajPodpis);

// ---------------------------
// BUSINESS: my club (owner-only)
// ---------------------------
app.get("/business/clubs/me", requireAuth, requireClub(), async (req, res) => {
  try {
    if (!req.klub.clubId) return res.status(404).send("Club not found.");
    const r = await pool.query(
      `SELECT ${STOLPCI_KLUBA_LASTNIKA} FROM clubs WHERE id=$1`,
      [req.klub.clubId]
    );

    if (r.rows.length === 0) return res.status(404).send("Club not found.");
    return res.status(200).json({ ...r.rows[0], my_role: req.klub.role });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.patch("/business/clubs/me", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    if (!req.klub.clubId) return res.status(404).send("Club not found.");
    const clubId = req.klub.clubId;

    // whitelist fields (snake_case) + allow camelCase inputs too
    const body = req.body || {};

    const incoming = {
      name: body.name,
      description: body.description,
      logo_url: body.logo_url ?? body.logoUrl,
      banner_url: body.banner_url ?? body.bannerUrl,
      contact_email: body.contact_email ?? body.contactEmail,
      contact_phone: body.contact_phone ?? body.contactPhone,
      instagram: body.instagram,
      website: body.website,
      address: body.address,
      city: body.city,
      country: body.country,
      lat: body.lat,
      lng: body.lng,
      // Doslej ju lastnik ni mogel nastaviti (samo admin) — ClubInfoView ju rabi.
      genres: body.genres,
      min_age: body.min_age ?? body.minAge,
      // Cenik bara (migracija 014). Poslje se cel seznam; prazen seznam = brez cenika.
      bar_prices: body.bar_prices ?? body.barPrices,
      // Slideshow (do 3 slike) in predstavitveni video (migracija 015).
      gallery_urls: body.gallery_urls ?? body.galleryUrls,
      video_url: body.video_url ?? body.videoUrl
    };

    // URL slike/videa: https, brez presledkov, razumna dolzina. Prazen niz je dovoljen (odstrani).
    const veljavenUrl = (u) => typeof u === "string" && u.length <= 500 && /^https:\/\/\S+$/.test(u);
    if (incoming.gallery_urls !== undefined) {
      if (!Array.isArray(incoming.gallery_urls)) return res.status(400).send("galleryUrls must be an array.");
      const g = incoming.gallery_urls.map(u => String(u ?? "").trim()).filter(u => u.length > 0);
      if (g.length > 3) return res.status(400).send("galleryUrls: at most 3 images.");
      if (!g.every(veljavenUrl)) return res.status(400).send("galleryUrls: each item must be an https URL.");
      incoming.gallery_urls = g;
    }
    if (incoming.video_url !== undefined) {
      const v = String(incoming.video_url ?? "").trim();
      if (v !== "" && !veljavenUrl(v)) return res.status(400).send("videoUrl must be an https URL.");
      incoming.video_url = v;
    }

    if (incoming.bar_prices !== undefined) {
      const c = preveriCenik(incoming.bar_prices);
      if (c.napaka) return res.status(400).send(c.napaka);
      // pg bi JS seznam poslal kot Postgresov ARRAY, ne kot JSON -> vedno JSON.stringify + ::jsonb.
      incoming.bar_prices = JSON.stringify(c.postavke);
    }

    if (incoming.genres !== undefined) {
      if (!Array.isArray(incoming.genres)) return res.status(400).send("genres must be an array.");
      incoming.genres = [...new Set(incoming.genres.map(g => String(g).trim().toLowerCase()))];
      const neznani = incoming.genres.filter(g => !ZANRI.includes(g));
      if (neznani.length) return res.status(400).json({ error: "unknown_genres", unknown: neznani, allowed: ZANRI });
    }
    if (incoming.min_age !== undefined) {
      const n = Number(incoming.min_age);
      if (!Number.isInteger(n) || n < 0 || n > 99) return res.status(400).send("minAge must be between 0 and 99.");
      incoming.min_age = n;
    }

    // build dynamic UPDATE only for provided keys
    const sets = [];
    const values = [];
    let idx = 1;

    for (const [k, v] of Object.entries(incoming)) {
      if (v === undefined) continue;
      sets.push(k === "bar_prices" ? `${k} = $${idx++}::jsonb` : `${k} = $${idx++}`);
      values.push(v);
    }

    if (sets.length === 0) {
      // nothing to update -> return current club
      const cur = await pool.query(`SELECT ${STOLPCI_KLUBA_LASTNIKA} FROM clubs WHERE id=$1`, [clubId]);
      return res.status(200).json(cur.rows[0]);
    }

    if (incoming.name !== undefined && String(incoming.name).trim().length === 0) {
      return res.status(400).send("Club name is required.");
    }
    // Koordinati v paru; posamezno ju baza zavrne (clubs_coords_chk).
    if ((incoming.lat === undefined) !== (incoming.lng === undefined)) {
      return res.status(400).send("lat and lng must be sent together.");
    }

    values.push(clubId);
    const sql = `UPDATE clubs SET ${sets.join(", ")} WHERE id = $${idx} RETURNING ${STOLPCI_KLUBA_LASTNIKA}`;

    const updated = await pool.query(sql, values);
    return res.status(200).json(updated.rows[0]);
  } catch (e) {
    // Omejitev v bazi (prazno ime, koordinate izven obsega, min_age ...) -> 400, ne 500.
    if (e && e.code === "23514") return res.status(400).send("Invalid club data: " + (e.constraint || "constraint"));
    if (e && e.code === "22P02") return res.status(400).send("Invalid value type.");
    console.error(e);
    return res.status(500).send("Server error.");
  }
});


// ---------------------------
// EVENTS (updated: upcoming true/false + time_status + ticket fields)
// ---------------------------
// Stolpci dogodka na enem mestu (javni GET /events, GET /events/:id, GET /business/events).
const STOLPCI_DOGODKA = `
        id,
        club_id,
        title,
        description,
        poster_url,
        start_at,
        end_at,
        min_age,
        genres,
        status,
        created_at,
        ticket_price_cents,
        currency,
        ticket_url,
        capacity,
        sold_count,
        -- Zaloga za oznake v aplikaciji ("Sold out", "Few left"). sold_count vodi
        -- sprozilec iz migracije 002; capacity NULL = brez omejitve.
        CASE
          WHEN ticket_price_cents IS NULL THEN 'external'
          WHEN capacity IS NOT NULL AND sold_count >= capacity THEN 'sold_out'
          WHEN capacity IS NOT NULL AND capacity - sold_count <= GREATEST(5, capacity / 10) THEN 'few_left'
          ELSE 'available'
        END AS availability,
        CASE
          WHEN start_at > NOW() THEN 'coming_soon'
          ELSE 'popular'
        END AS time_status`;

// Vsi dogodki lastnega kluba, tudi osnutki in odpovedani. Samo za lastnika.
app.get("/business/events", requireAuth, requireClub(), async (req, res) => {
  try {
    if (!req.klub.clubId) return res.status(404).send("Club not found.");

    const r = await pool.query(
      `SELECT ${STOLPCI_DOGODKA} FROM events WHERE club_id=$1 ORDER BY start_at DESC LIMIT 500`,
      [req.klub.clubId]
    );
    return res.status(200).json(r.rows);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.get("/events", async (req, res) => {
  try {
    const { clubId, upcoming } = req.query;

    const params = [];
    const where = [];

    if (clubId) {
      params.push(clubId);
      where.push(`club_id = $${params.length}`);
    }

    // coming soon vs popular. Pretekli dogodki so javno vidni samo 7 dni po zacetku
    // (Martin, 16. 9. 2026): stran kluba in "hit tedna" na domacem zaslonu kazeta samo
    // zadnji teden, starejsi izginejo. V bazi ostanejo (vstopnice, narocila, zgodovina
    // kluba v GET /business/events); GET /events/:id jih se vrne (povezava z vstopnice).
    if (upcoming === "true") where.push(`start_at > NOW()`);
    if (upcoming === "false") where.push(`start_at <= NOW() AND start_at > NOW() - INTERVAL '7 days'`);

    // Javno so vidni SAMO objavljeni dogodki. Osnutki in odpovedani so bili
    // doslej vidni vsakomur; lastnik jih vidi prek GET /business/events.
    where.push(`status = 'published'`);
    // Dogodki skritih klubov javno niso vidni (migracija 006).
    where.push(`club_id NOT IN (SELECT id FROM clubs WHERE hidden)`);

    const sql = `
      SELECT ${STOLPCI_DOGODKA}
      FROM events
      WHERE ${where.join(" AND ")}
      ORDER BY start_at ASC
      LIMIT 200
    `;

    const r = await pool.query(sql, params);
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

app.get("/events/:id", async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).send("Invalid event id.");
    const r = await pool.query(
      `SELECT ${STOLPCI_DOGODKA} FROM events
       WHERE id=$1 AND status='published'
         AND club_id NOT IN (SELECT id FROM clubs WHERE hidden)`,
      [req.params.id]
    );

    if (r.rows.length === 0) return res.status(404).send("Event not found.");
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// POST /events (updated: accepts camelCase + snake_case, includes ticket fields)
app.post("/events", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    // accept both formats
    const clubId = req.body.clubId ?? req.body.club_id;
    const title = req.body.title;
    const description = req.body.description ?? "";
    const posterUrl = req.body.posterUrl ?? req.body.poster_url ?? "";
    const startAt = req.body.startAt ?? req.body.start_at;
    const endAt = req.body.endAt ?? req.body.end_at ?? null;
    const minAge = req.body.minAge ?? req.body.min_age;
    const genres = req.body.genres;
    const status = req.body.status ?? "published";

    const ticketPriceCents = req.body.ticketPriceCents ?? req.body.ticket_price_cents ?? null;
    const currency = (req.body.currency ?? "EUR").toString();
    const ticketUrl = (req.body.ticketUrl ?? req.body.ticket_url ?? "").toString();
    const capacity = req.body.capacity ?? null;
    if (capacity !== null) {
      const c = Number(capacity);
      if (!Number.isInteger(c) || c < 1 || c > 100000) return res.status(400).send("capacity must be a positive integer.");
    }

    if (!clubId || !title || !startAt) return res.status(400).send("Missing clubId, title or startAt.");
    if (!/^\d+$/.test(String(clubId))) return res.status(400).send("Invalid clubId.");
    if (String(title).trim().length === 0) return res.status(400).send("Title is required.");
    if (Number.isNaN(new Date(startAt).getTime())) return res.status(400).send("startAt must be a valid date.");
    if (endAt !== null && Number.isNaN(new Date(endAt).getTime())) return res.status(400).send("endAt must be a valid date.");
    if (!["draft", "published", "cancelled"].includes(status)) {
      return res.status(400).send("status must be draft, published or cancelled.");
    }
    if (ticketPriceCents !== null) {
      const c = Number(ticketPriceCents);
      if (!Number.isInteger(c) || c < 0) return res.status(400).send("ticketPriceCents must be a non-negative integer.");
    }
    if (genres !== undefined && !Array.isArray(genres)) return res.status(400).send("genres must be an array.");
    if (minAge !== undefined && minAge !== null) {
      const a = Number(minAge);
      if (!Number.isInteger(a) || a < 0 || a > 99) return res.status(400).send("minAge must be between 0 and 99.");
    }

    const clubR = await pool.query("SELECT id, owner_user_id, min_age, genres FROM clubs WHERE id=$1", [clubId]);
    if (clubR.rows.length === 0) return res.status(404).send("Club not found.");

    const club = clubR.rows[0];

    if (req.klub.role !== "admin" && Number(club.id) !== Number(req.klub.clubId)) {
      return res.status(403).send("You can only create events for your own club.");
    }

    const finalMinAge = (minAge ?? club.min_age ?? 18);
    const finalGenres = Array.isArray(genres) ? genres : (club.genres || []);

    const r = await pool.query(
      `INSERT INTO events
      (
        club_id, title, description, poster_url, start_at, end_at,
        min_age, genres, status,
        ticket_price_cents, currency, ticket_url, capacity
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING *`,
      [
        clubId,
        title,
        description,
        posterUrl,
        startAt,
        endAt,
        finalMinAge,
        finalGenres,
        status,
        ticketPriceCents,
        currency,
        ticketUrl,
        capacity
      ]
    );

    res.status(201).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// Ali je migracija 002 (placila) ze pognana? Od nje naprej se racun ne sme
// vec trdo izbrisati, ker so narocila racunovodski dokumenti.
let obstajajoNarocila = false;
pool.query("SELECT to_regclass('public.orders') IS NOT NULL AS obstaja")
  .then(r => {
    obstajajoNarocila = r.rows[0].obstaja;
    console.log(obstajajoNarocila
      ? "Tabela orders obstaja -> brisanje racuna anonimizira"
      : "Tabele orders se ni -> brisanje racuna je trd izbris");
  })
  .catch(e => console.error("Ne morem preveriti tabele orders:", e.message));

// ---------------------------
// DOGODKI: urejanje in odpoved
// ---------------------------
// Doslej je obstajal samo POST /events. Klub dogodka ni mogel ne popraviti
// ne umakniti — niti ce je vpisal napacen datum ali ceno.

// Preveri, da dogodek obstaja in da ga sme urejati prijavljeni uporabnik.
async function dogodekZaUrejanje(req, res) {
  if (!/^\d+$/.test(req.params.id)) { res.status(400).send("Invalid event id."); return null; }

  const r = await pool.query(
    `SELECT e.id, e.club_id, e.status, c.owner_user_id
     FROM events e JOIN clubs c ON c.id = e.club_id
     WHERE e.id = $1`,
    [req.params.id]
  );
  if (r.rows.length === 0) { res.status(404).send("Event not found."); return null; }

  const d = r.rows[0];
  if (req.klub.role !== "admin" && Number(d.club_id) !== Number(req.klub.clubId)) {
    res.status(403).send("You can only manage events of your own club.");
    return null;
  }
  return d;
}

app.patch("/events/:id", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const d = await dogodekZaUrejanje(req, res);
    if (!d) return;

    const b = req.body || {};
    const dovoljeno = {
      title:              b.title,
      description:        b.description,
      poster_url:         b.posterUrl        ?? b.poster_url,
      start_at:           b.startAt          ?? b.start_at,
      end_at:             b.endAt            ?? b.end_at,
      min_age:            b.minAge           ?? b.min_age,
      genres:             b.genres,
      status:             b.status,
      ticket_price_cents: b.ticketPriceCents ?? b.ticket_price_cents,
      currency:           b.currency,
      ticket_url:         b.ticketUrl        ?? b.ticket_url,
      capacity:           b.capacity,
    };

    if (dovoljeno.capacity !== undefined && dovoljeno.capacity !== null) {
      const c = Number(dovoljeno.capacity);
      if (!Number.isInteger(c) || c < 1 || c > 100000) return res.status(400).send("capacity must be a positive integer.");
    }
    if (dovoljeno.status !== undefined &&
        !["draft","published","cancelled"].includes(dovoljeno.status)) {
      return res.status(400).send("status must be draft, published or cancelled.");
    }
    if (dovoljeno.genres !== undefined && !Array.isArray(dovoljeno.genres)) {
      return res.status(400).send("genres must be an array.");
    }
    if (dovoljeno.ticket_price_cents !== undefined && dovoljeno.ticket_price_cents !== null) {
      const c = Number(dovoljeno.ticket_price_cents);
      if (!Number.isInteger(c) || c < 0) return res.status(400).send("ticketPriceCents must be a non-negative integer.");
    }

    const sets = [], vrednosti = [];
    for (const [k, v] of Object.entries(dovoljeno)) {
      if (v === undefined) continue;
      vrednosti.push(v);
      sets.push(`${k} = $${vrednosti.length}`);
    }
    if (sets.length === 0) return res.status(400).send("Nothing to update.");

    vrednosti.push(d.id);
    const r = await pool.query(
      `UPDATE events SET ${sets.join(", ")} WHERE id = $${vrednosti.length} RETURNING *`,
      vrednosti
    );
    return res.status(200).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.delete("/events/:id", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const d = await dogodekZaUrejanje(req, res);
    if (!d) return;

    // Ce so na dogodek prodane vstopnice, se NE brise. Kupci imajo vstopnice,
    // ki morajo ostati veljavne kot dokazilo, in narocilo je racunovodski
    // dokument. Dogodek se v tem primeru odpove, ne izbrise.
    if (obstajajoNarocila) {
      const n = await pool.query(
        "SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND status IN ('paid','partially_refunded')",
        [d.id]
      );
      if (n.rows[0].n > 0) {
        const r = await pool.query(
          "UPDATE events SET status='cancelled' WHERE id=$1 RETURNING *", [d.id]
        );
        return res.status(200).json({
          message: "Event has sold tickets and was cancelled instead of deleted.",
          orders: n.rows[0].n,
          event: r.rows[0],
        });
      }
    }

    await pool.query("DELETE FROM events WHERE id=$1", [d.id]);
    return res.status(200).json({ message: "Event deleted." });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// ISKANJE
// ---------------------------
// SearchView je doslej iskal na napravi, po prvih 100 klubih, ki jih je vrnil
// strezik, in samo po klubih — ceprav polje obljublja "Search clubs or events".
app.get("/search", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (q.length < 2) return res.status(400).send("Query must be at least 2 characters.");

    const limit = stevilo(req.query.limit, 20, 50);
    const vzorec = `%${q}%`;

    const [klubi, dogodki] = await Promise.all([
      pool.query(
        `SELECT id, name, city, logo_url, lat, lng, genres
         FROM clubs
         WHERE hidden = FALSE
           AND (name ILIKE $1 OR city ILIKE $1 OR description ILIKE $1)
         ORDER BY (name ILIKE $2) DESC, name
         LIMIT $3`,
        [vzorec, `${q}%`, limit]
      ),
      pool.query(
        `SELECT e.id, e.club_id, e.title, e.poster_url, e.start_at,
                e.ticket_price_cents, e.currency, c.name AS club_name
         FROM events e JOIN clubs c ON c.id = e.club_id
         WHERE e.status = 'published' AND c.hidden = FALSE
           AND (e.title ILIKE $1 OR e.description ILIKE $1 OR c.name ILIKE $1)
         ORDER BY (e.start_at > NOW()) DESC, e.start_at
         LIMIT $2`,
        [vzorec, limit]
      ),
    ]);

    return res.status(200).json({
      query: q,
      clubs: klubi.rows,
      events: dogodki.rows,
      total: klubi.rows.length + dogodki.rows.length,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// PROŠNJE USTVARJALCEV (javna oddaja) + ADMIN PANEL
// ---------------------------
// Do migracije 006 ni obstajala nobena pot, po kateri bi klub sploh nastal:
// prošnje s spletne strani so šle v Supabase, ki ga backend ne vidi, vlogo
// 'business' pa ni imel kdo dodeliti. Zdaj: aplikacija (ali kdorkoli) odda
// prošnjo sem, admin jo v panelu (/admin) odobri -> uporabnik dobi vlogo
// 'business' in prazen klub z imenom iz prošnje.
//
// Vse poti /admin/api/* zahtevajo vlogo admin (requireRole). Aplikacija in
// panel vlogo samo kažeta; uveljavlja jo strežnik.

const STOLPCI_PROSNJE = `id, user_id, business_name, business_type, business_address, city,
  licence_id, contact_name, contact_role, email, phone, message,
  status, decided_at, decided_by, decision_note, club_id, created_at`;

// Uporabnik brez password_hash in brez ničesar, kar bi bilo za panel odveč.
const ADMIN_POLJA_UPORABNIKA = `id, email, username, role, email_verified, avatar_url,
  phone, date_of_birth, country, onboarded_at, failed_login_count, locked_until, created_at`;

// Klub za admina: javni stolpci + hidden + stanje Stripa (brez stripe_account_id,
// ki ga panel ne potrebuje in ki ne sme uhajati nikamor).
const ADMIN_STOLPCI_KLUBA = `c.id, c.owner_user_id, c.name, c.logo_url, c.banner_url, c.description,
  c.contact_email, c.contact_phone, c.instagram, c.website, c.address, c.city, c.country,
  c.lat, c.lng, c.min_age, c.genres, c.hidden, c.stripe_charges_enabled, c.created_at,
  u.email AS owner_email, u.username AS owner_username`;

const VELJAVEN_EMAIL = /^[^@\s]+@[^@\s.]+\.[^@\s]+$/;

function besedilo(v, najvec) {
  if (v === undefined || v === null) return "";
  return String(v).trim().slice(0, najvec);
}

// Neobvezna prijava: če je žeton priložen in veljaven, req.user obstaja;
// če ga ni ali je neveljaven, pot vseeno teče naprej (kot neprijavljen).
async function neobveznaPrijava(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return next();
  try { req.user = await razberiUporabnika(token); } catch (_) { /* neprijavljen */ }
  next();
}

// POST /creator-applications — javno, omejeno. Aplikacija ga kliče iz
// "Request for creator"; prijavljenemu uporabniku se prošnja veže na račun.
// Maili ob novi prošnji: obvestilo ekipi (TEAM_EMAIL, več naslovov z vejico;
// privzeto luka@outly.si, fedja@outly.si) in potrdilo prijavitelju. Do 11. 9. 2026
// je to za spletni obrazec delal Supabase/Brevo; zdaj spletna stran in
// aplikacija uporabljata isto pot, zato maili tu. Napaka pri pošiljanju NE
// podre prošnje (ta je že shranjena).
function ubeziHtml(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
async function posljiMailProsnja(p) {
  if (!resend) return;
  const from = process.env.EMAIL_FROM || "onboarding@resend.dev";
  const appName = process.env.APP_NAME || "Outly";
  const ekipa = String(process.env.TEAM_EMAIL || "luka@outly.si,fedja@outly.si").split(",").map(e => e.trim()).filter(Boolean);
  const vrstica = (k, v) => v ? `<tr><td style="padding:4px 12px 4px 0;color:#666">${k}</td><td style="padding:4px 0"><b>${ubeziHtml(v)}</b></td></tr>` : "";
  try {
    const r1 = await resend.emails.send({
      from, to: ekipa, replyTo: p.email,
      subject: `Nova prošnja ustvarjalca: ${p.businessName}`,
      html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – nova prošnja ustvarjalca (#${p.id})</h2>
      <table>${vrstica("Podjetje", p.businessName)}${vrstica("Vrsta", p.businessType)}${vrstica("Naslov", p.businessAddress)}${vrstica("Kraj", p.city)}${vrstica("Licenca", p.licenceId)}${vrstica("Kontakt", p.contactName)}${vrstica("Vloga", p.contactRole)}${vrstica("E-naslov", p.email)}${vrstica("Telefon", p.phone)}${vrstica("Sporočilo", p.message)}${vrstica("Vir", p.userId ? "aplikacija (uporabnik #" + p.userId + ")" : "spletna stran")}</table>
      <p>Odobri ali zavrni v admin panelu: <a href="https://outly-backend-roy3.onrender.com/admin/">outly-backend-roy3.onrender.com/admin</a> → Prošnje.</p>
    </div>`,
    });
    if (r1 && r1.error) console.error("Resend napaka (prošnja, ekipa):", JSON.stringify(r1.error));
    const r2 = await resend.emails.send({
      from, to: p.email,
      subject: `We received your application, ${p.contactName}`,
      html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – application received</h2>
      <p>Thanks for applying to bring <b>${ubeziHtml(p.businessName)}</b> to ${appName}.</p>
      <p>A real person reads every application. If we need documents — business licence, proof of ownership, tax number or bank details — we will ask for them in our reply. Please don't send them before we ask.</p>
      <p>We'll get back to you at this address.</p>
    </div>`,
    });
    if (r2 && r2.error) console.error("Resend napaka (prošnja, potrdilo):", JSON.stringify(r2.error));
  } catch (e) { console.error("Resend napaka (prošnja):", e); }
}

app.post("/creator-applications", omeji({ kljuc: "prosnja", najvec: 5, oknoSekund: 3600 }), neobveznaPrijava, async (req, res) => {
  try {
    const b = req.body || {};
    if (typeof b !== "object" || Array.isArray(b)) return res.status(400).send("Invalid body.");

    const businessName = besedilo(b.businessName ?? b.business_name, 120);
    const contactName  = besedilo(b.contactName  ?? b.contact_name, 120);
    // Prijavljeni uporabnik: e-naslov je njegov, ne more oddati prošnje za tujega.
    const email = (req.user ? String(req.user.email) : besedilo(b.email, 254)).toLowerCase();

    if (businessName.length < 2) return res.status(400).send("businessName is required (2-120 characters).");
    if (contactName.length < 2)  return res.status(400).send("contactName is required (2-120 characters).");
    if (!VELJAVEN_EMAIL.test(email)) return res.status(400).send("Valid email is required.");

    const phoneRaw = besedilo(b.phone, 40).replace(/[\s\-()]/g, "");
    if (phoneRaw && !/^\+?[0-9]{6,15}$/.test(phoneRaw)) {
      return res.status(400).send("phone must contain 6-15 digits, optionally with leading +.");
    }

    const r = await pool.query(
      `INSERT INTO creator_applications
        (user_id, business_name, business_type, business_address, city, licence_id,
         contact_name, contact_role, email, phone, message)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING id, status, created_at`,
      [
        req.user ? req.user.userId : null,
        businessName,
        besedilo(b.businessType ?? b.business_type, 80),
        besedilo(b.businessAddress ?? b.business_address, 200),
        besedilo(b.city, 80),
        besedilo(b.licenceId ?? b.licence_id, 80),
        contactName,
        besedilo(b.contactRole ?? b.contact_role, 80),
        email,
        phoneRaw,
        besedilo(b.message, 2000),
      ]
    );
    console.log("Nova prošnja ustvarjalca:", r.rows[0].id, businessName, email);
    posljiMailProsnja({
      id: r.rows[0].id, userId: req.user ? req.user.userId : null, businessName, contactName, email, phone: phoneRaw,
      businessType: besedilo(b.businessType ?? b.business_type, 80), businessAddress: besedilo(b.businessAddress ?? b.business_address, 200),
      city: besedilo(b.city, 80), licenceId: besedilo(b.licenceId ?? b.licence_id, 80), contactRole: besedilo(b.contactRole ?? b.contact_role, 80),
      message: besedilo(b.message, 2000),
    }).catch(() => {});
    return res.status(201).json({
      message: "Application received. We will review it and get back to you by email.",
      id: r.rows[0].id, status: r.rows[0].status, createdAt: r.rows[0].created_at,
    });
  } catch (e) {
    // Odprta prošnja s tem e-naslovom že obstaja (ca_email_open_key).
    if (e && e.code === "23505") return res.status(409).send("An application for this email is already pending.");
    if (e && e.code === "23514") return res.status(400).send("Invalid application data.");
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Prijavljeni uporabnik vidi svoje prošnje (aplikacija pokaže "prošnja oddana / odobrena / zavrnjena").
app.get("/creator-applications/me", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, business_name, status, decided_at, decision_note, club_id, created_at
       FROM creator_applications
       WHERE user_id = $1 OR LOWER(email) = LOWER($2)
       ORDER BY created_at DESC LIMIT 20`,
      [req.user.userId, req.user.email]
    );
    return res.status(200).json(r.rows);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Vse pod /admin/api zahteva admina. Napaka je namenoma enaka za "ni žetona"
// (401) in "napačna vloga" (403) kot drugod.
const admin = express.Router();
admin.use(requireAuth, requireRole("admin"));

function celoId(v) { return /^\d+$/.test(String(v)) ? Number(v) : null; }

// --- pregled ---
admin.get("/summary", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT
        (SELECT COUNT(*)::int FROM creator_applications WHERE status='new') AS new_applications,
        (SELECT COUNT(*)::int FROM clubs)                                    AS clubs,
        (SELECT COUNT(*)::int FROM clubs WHERE hidden)                       AS hidden_clubs,
        (SELECT COUNT(*)::int FROM users)                                    AS users,
        (SELECT COUNT(*)::int FROM users WHERE role='business')              AS business_users,
        (SELECT COUNT(*)::int FROM users WHERE role='admin')                 AS admins,
        (SELECT COUNT(*)::int FROM events)                                   AS events,
        (SELECT COUNT(*)::int FROM events WHERE status='published' AND start_at > NOW()) AS upcoming_events`);
    return res.json(r.rows[0]);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- prošnje ---
admin.get("/creator-applications", async (req, res) => {
  try {
    const status = String(req.query.status || "new");
    if (!["new", "approved", "rejected", "all"].includes(status)) {
      return res.status(400).send("status must be new, approved, rejected or all.");
    }
    const p = [];
    let kje = "";
    if (status !== "all") { p.push(status); kje = "WHERE status = $1"; }
    const r = await pool.query(
      `SELECT ${STOLPCI_PROSNJE} FROM creator_applications ${kje}
       ORDER BY (status='new') DESC, created_at DESC LIMIT 500`, p
    );
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Odobri: uporabnik z e-naslovom prošnje dobi vlogo business in prazen klub.
admin.post("/creator-applications/:id/approve", async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid application id.");
  const opomba = besedilo((req.body || {}).note, 500);

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    // FOR UPDATE: dva admina ne moreta iste prošnje odobriti dvakrat.
    const pr = await c.query(
      `SELECT ${STOLPCI_PROSNJE} FROM creator_applications WHERE id=$1 FOR UPDATE`, [id]
    );
    if (pr.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Application not found."); }
    const p = pr.rows[0];
    if (p.status !== "new") { await c.query("ROLLBACK"); return res.status(409).send(`Application already ${p.status}.`); }

    // Uporabnik: po vezi na račun ali po e-naslovu (male črke, kot pri registraciji).
    const ur = await c.query(
      `SELECT id, email, role, email_verified FROM users
       WHERE id = $1 OR email = $2 ORDER BY (id = $1) DESC LIMIT 1 FOR UPDATE`,
      [p.user_id ?? -1, p.email.toLowerCase()]
    );
    if (ur.rows.length === 0) {
      await c.query("ROLLBACK");
      return res.status(409).json({
        error: "user_not_found",
        message: `No Outly account with email ${p.email}. The applicant must register in the app first.`,
      });
    }
    const u = ur.rows[0];

    // Poslovni del aplikacije vidi samo PRVI klub lastnika (LIMIT 1). Drugi
    // klub bi bil neviden in neurejljiv — zato ne ustvarjamo drugega.
    const ima = await c.query("SELECT id, name FROM clubs WHERE owner_user_id=$1 LIMIT 1", [u.id]);
    if (ima.rows.length > 0) {
      await c.query("ROLLBACK");
      return res.status(409).json({
        error: "user_has_club",
        message: `User ${u.email} already owns club "${ima.rows[0].name}" (id ${ima.rows[0].id}).`,
      });
    }

    // Admin ostane admin (requireRole admina povsod spusti); navaden uporabnik postane business.
    if (u.role === "user") await c.query("UPDATE users SET role='business' WHERE id=$1", [u.id]);

    const kr = await c.query(
      `INSERT INTO clubs (owner_user_id, name, address, city, contact_email, contact_phone)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name`,
      [u.id, p.business_name, p.business_address, p.city, p.email, p.phone]
    );

    const posodobljena = await c.query(
      `UPDATE creator_applications
       SET status='approved', decided_at=NOW(), decided_by=$2, decision_note=$3, club_id=$4
       WHERE id=$1 RETURNING ${STOLPCI_PROSNJE}`,
      [id, req.user.userId, opomba, kr.rows[0].id]
    );
    // Vloga je v JWT: stari dostopni žeton velja še do 1 h, osvežitev prinese novo vlogo.
    await c.query("COMMIT");
    console.log(`Prošnja ${id} odobrena (admin ${req.user.userId}): uporabnik ${u.id} -> business, klub ${kr.rows[0].id}`);
    return res.status(200).json({ application: posodobljena.rows[0], club: kr.rows[0], userId: u.id, userEmail: u.email });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (e && e.code === "23514") return res.status(400).send("Application data violates club constraints: " + (e.constraint || ""));
    console.error(e);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

admin.post("/creator-applications/:id/reject", async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid application id.");
    const opomba = besedilo((req.body || {}).note, 500);
    const r = await pool.query(
      `UPDATE creator_applications
       SET status='rejected', decided_at=NOW(), decided_by=$2, decision_note=$3
       WHERE id=$1 AND status='new' RETURNING ${STOLPCI_PROSNJE}`,
      [id, req.user.userId, opomba]
    );
    if (r.rows.length === 0) {
      const obstaja = await pool.query("SELECT status FROM creator_applications WHERE id=$1", [id]);
      if (obstaja.rows.length === 0) return res.status(404).send("Application not found.");
      return res.status(409).send(`Application already ${obstaja.rows[0].status}.`);
    }
    return res.status(200).json(r.rows[0]);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- klubi ---
admin.get("/clubs", async (req, res) => {
  try {
    const p = [];
    let kje = "";
    if (req.query.q) { p.push(`%${String(req.query.q).trim()}%`); kje = `WHERE c.name ILIKE $1 OR c.city ILIKE $1 OR u.email ILIKE $1`; }
    const r = await pool.query(
      `SELECT ${ADMIN_STOLPCI_KLUBA},
              (SELECT COUNT(*)::int FROM events e WHERE e.club_id = c.id) AS event_count
       FROM clubs c LEFT JOIN users u ON u.id = c.owner_user_id
       ${kje} ORDER BY c.created_at DESC LIMIT 500`, p
    );
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Skupno preverjanje polj kluba za POST in PATCH. Vrne { sets, vrednosti } ali napako.
function poljaKluba(b, zaVstavljanje) {
  const out = {};
  const bes = (kljuc, ...imena) => {
    for (const ime of imena) if (b[ime] !== undefined) { out[kljuc] = b[ime] === null ? "" : String(b[ime]).trim(); return; }
  };
  bes("name", "name");
  bes("description", "description");
  bes("logo_url", "logoUrl", "logo_url");
  bes("banner_url", "bannerUrl", "banner_url");
  bes("contact_email", "contactEmail", "contact_email");
  bes("contact_phone", "contactPhone", "contact_phone");
  bes("instagram", "instagram");
  bes("website", "website");
  bes("address", "address");
  bes("city", "city");
  bes("country", "country");

  if (out.name !== undefined && (out.name.length === 0 || out.name.length > 120)) return { napaka: "name is required (1-120 characters)." };
  if (out.contact_email !== undefined && out.contact_email && !VELJAVEN_EMAIL.test(out.contact_email)) return { napaka: "contactEmail is not a valid email." };
  for (const k of ["logo_url", "banner_url", "website"]) {
    if (out[k] && !/^https?:\/\//i.test(out[k])) return { napaka: `${k} must start with http:// or https://.` };
    if (out[k] && out[k].length > 500) return { napaka: `${k} too long.` };
  }
  if (out.description !== undefined && out.description.length > 5000) return { napaka: "description too long (max 5000)." };

  const lat = b.lat, lng = b.lng;
  if ((lat === undefined) !== (lng === undefined)) return { napaka: "lat and lng must be sent together." };
  if (lat !== undefined) {
    if (lat === null && lng === null) { out.lat = null; out.lng = null; }
    else {
      const a = Number(lat), o = Number(lng);
      if (!Number.isFinite(a) || !Number.isFinite(o) || a < -90 || a > 90 || o < -180 || o > 180) return { napaka: "lat/lng out of range." };
      out.lat = a; out.lng = o;
    }
  }
  const minAge = b.minAge ?? b.min_age;
  if (minAge !== undefined) {
    const n = Number(minAge);
    if (!Number.isInteger(n) || n < 0 || n > 99) return { napaka: "minAge must be an integer 0-99." };
    out.min_age = n;
  }
  if (b.genres !== undefined) {
    if (!Array.isArray(b.genres)) return { napaka: "genres must be an array." };
    const izbrani = [...new Set(b.genres.map(g => String(g).trim().toLowerCase()))];
    const neznani = izbrani.filter(g => !ZANRI.includes(g));
    if (neznani.length) return { napaka: `unknown genres: ${neznani.join(", ")}` };
    out.genres = izbrani;
  }
  if (b.hidden !== undefined) {
    if (typeof b.hidden !== "boolean") return { napaka: "hidden must be true or false." };
    out.hidden = b.hidden;
  }
  if (zaVstavljanje && out.name === undefined) return { napaka: "name is required." };
  return { polja: out };
}

async function lastnikPoEmailu(c, email) {
  const e = String(email || "").trim().toLowerCase();
  if (!VELJAVEN_EMAIL.test(e)) return { napaka: "ownerEmail is not a valid email." };
  const r = await c.query("SELECT id, email, role FROM users WHERE email=$1", [e]);
  if (r.rows.length === 0) return { napaka: `No account with email ${e}. The owner must register in the app first.` };
  return { uporabnik: r.rows[0] };
}

admin.post("/clubs", async (req, res) => {
  const b = req.body || {};
  const c = await pool.connect();
  try {
    if (b.ownerEmail === undefined && b.owner_email === undefined) return res.status(400).send("ownerEmail is required.");
    const pk = poljaKluba(b, true);
    if (pk.napaka) return res.status(400).send(pk.napaka);

    await c.query("BEGIN");
    const l = await lastnikPoEmailu(c, b.ownerEmail ?? b.owner_email);
    if (l.napaka) { await c.query("ROLLBACK"); return res.status(400).send(l.napaka); }
    const u = l.uporabnik;

    const ima = await c.query("SELECT id, name FROM clubs WHERE owner_user_id=$1 LIMIT 1", [u.id]);
    if (ima.rows.length > 0) {
      await c.query("ROLLBACK");
      return res.status(409).send(`User ${u.email} already owns club "${ima.rows[0].name}" (id ${ima.rows[0].id}). One club per business account.`);
    }
    if (u.role === "user") await c.query("UPDATE users SET role='business' WHERE id=$1", [u.id]);

    const stolpci = ["owner_user_id", ...Object.keys(pk.polja)];
    const vrednosti = [u.id, ...Object.values(pk.polja)];
    const r = await c.query(
      `INSERT INTO clubs (${stolpci.join(", ")})
       VALUES (${vrednosti.map((_, i) => `$${i + 1}`).join(", ")}) RETURNING id`,
      vrednosti
    );
    const nov = await c.query(
      `SELECT ${ADMIN_STOLPCI_KLUBA}, 0 AS event_count FROM clubs c LEFT JOIN users u ON u.id=c.owner_user_id WHERE c.id=$1`,
      [r.rows[0].id]
    );
    await c.query("COMMIT");
    return res.status(201).json(nov.rows[0]);
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (e && e.code === "23514") return res.status(400).send("Invalid club data: " + (e.constraint || "constraint"));
    console.error(e);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

admin.patch("/clubs/:id", async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid club id.");
  const b = req.body || {};
  const c = await pool.connect();
  try {
    const pk = poljaKluba(b, false);
    if (pk.napaka) return res.status(400).send(pk.napaka);
    const polja = pk.polja;

    await c.query("BEGIN");
    const obstaja = await c.query("SELECT id, owner_user_id FROM clubs WHERE id=$1 FOR UPDATE", [id]);
    if (obstaja.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Club not found."); }

    // Prenos lastništva po e-naslovu. Novi lastnik ne sme že imeti kluba.
    const novEmail = b.ownerEmail ?? b.owner_email;
    if (novEmail !== undefined) {
      const l = await lastnikPoEmailu(c, novEmail);
      if (l.napaka) { await c.query("ROLLBACK"); return res.status(400).send(l.napaka); }
      if (l.uporabnik.id !== obstaja.rows[0].owner_user_id) {
        const ima = await c.query("SELECT id FROM clubs WHERE owner_user_id=$1 AND id<>$2 LIMIT 1", [l.uporabnik.id, id]);
        if (ima.rows.length > 0) { await c.query("ROLLBACK"); return res.status(409).send(`User ${l.uporabnik.email} already owns another club.`); }
        if (l.uporabnik.role === "user") await c.query("UPDATE users SET role='business' WHERE id=$1", [l.uporabnik.id]);
        polja.owner_user_id = l.uporabnik.id;
      }
    }

    const kljuci = Object.keys(polja);
    if (kljuci.length === 0) { await c.query("ROLLBACK"); return res.status(400).send("Nothing to update."); }
    const vrednosti = Object.values(polja);
    vrednosti.push(id);
    await c.query(
      `UPDATE clubs SET ${kljuci.map((k, i) => `${k} = $${i + 1}`).join(", ")} WHERE id = $${vrednosti.length}`,
      vrednosti
    );
    const r = await c.query(
      `SELECT ${ADMIN_STOLPCI_KLUBA}, (SELECT COUNT(*)::int FROM events e WHERE e.club_id=c.id) AS event_count
       FROM clubs c LEFT JOIN users u ON u.id=c.owner_user_id WHERE c.id=$1`, [id]
    );
    await c.query("COMMIT");
    return res.status(200).json(r.rows[0]);
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (e && e.code === "23514") return res.status(400).send("Invalid club data: " + (e.constraint || "constraint"));
    if (e && e.code === "22P02") return res.status(400).send("Invalid value type.");
    console.error(e);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

// --- uporabniki ---
admin.get("/users", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    const p = [];
    let kje = "";
    if (q) { p.push(`%${q}%`); kje = "WHERE email ILIKE $1 OR username ILIKE $1"; }
    const r = await pool.query(
      `SELECT ${ADMIN_POLJA_UPORABNIKA},
              (SELECT COUNT(*)::int FROM clubs c WHERE c.owner_user_id = users.id) AS club_count
       FROM users ${kje} ORDER BY created_at DESC LIMIT 200`, p
    );
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// PATCH /admin/api/users/:id — { role } | { unlock: true } | { emailVerified: true }
admin.patch("/users/:id", async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid user id.");
    const b = req.body || {};
    const sets = [], vrednosti = [];
    const dodaj = (k, v) => { vrednosti.push(v); sets.push(`${k} = $${vrednosti.length}`); };
    let prekliciZetone = false;

    if (b.role !== undefined) {
      if (!["user", "business", "admin"].includes(b.role)) return res.status(400).send("role must be user, business or admin.");
      // Admin si sam ne more vzeti vloge: sicer bi lahko ostal panel brez admina.
      if (id === req.user.userId && b.role !== "admin") return res.status(400).send("You cannot remove your own admin role.");
      dodaj("role", b.role);
      prekliciZetone = true;
    }
    if (b.unlock !== undefined) {
      if (b.unlock !== true) return res.status(400).send("unlock must be true.");
      dodaj("failed_login_count", 0);
      dodaj("locked_until", null);
    }
    // Ročna potrditev e-naslova: nadomešča migracijo 005, dokler Resend ne
    // pošilja vsem (domena outly.si še ni potrjena).
    if (b.emailVerified !== undefined) {
      if (b.emailVerified !== true) return res.status(400).send("emailVerified can only be set to true.");
      dodaj("email_verified", true);
    }
    if (sets.length === 0) return res.status(400).send("Nothing to update.");

    vrednosti.push(id);
    const r = await pool.query(
      `UPDATE users SET ${sets.join(", ")} WHERE id = $${vrednosti.length}
       RETURNING ${ADMIN_POLJA_UPORABNIKA}`, vrednosti
    );
    if (r.rows.length === 0) return res.status(404).send("User not found.");
    // Vloga pride iz baze ob vsakem klicu (Supabase Auth), preklic žetonov ni več potreben.
    console.log(`Admin ${req.user.userId} spremenil uporabnika ${id}:`, JSON.stringify(b));
    return res.status(200).json(r.rows[0]);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- dogodki ---
admin.get("/events", async (req, res) => {
  try {
    const p = [];
    const pogoji = [];
    if (req.query.status) {
      if (!["draft", "published", "cancelled"].includes(String(req.query.status))) return res.status(400).send("Invalid status.");
      p.push(String(req.query.status)); pogoji.push(`e.status = $${p.length}`);
    }
    if (req.query.clubId) {
      const cid = celoId(req.query.clubId);
      if (!cid) return res.status(400).send("Invalid clubId.");
      p.push(cid); pogoji.push(`e.club_id = $${p.length}`);
    }
    const kje = pogoji.length ? "WHERE " + pogoji.join(" AND ") : "";
    const r = await pool.query(
      `SELECT e.id, e.club_id, c.name AS club_name, c.hidden AS club_hidden, e.title, e.poster_url,
              e.start_at, e.end_at, e.min_age, e.genres, e.status, e.ticket_price_cents, e.currency,
              e.ticket_url, e.created_at
       FROM events e JOIN clubs c ON c.id = e.club_id
       ${kje} ORDER BY e.start_at DESC LIMIT 500`, p
    );
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Umik dogodka: status -> cancelled. Ne briše: če bodo kdaj prodane vstopnice,
// so naročila računovodski dokument (glej DELETE /events/:id).
admin.patch("/events/:id", async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const status = (req.body || {}).status;
    if (!["draft", "published", "cancelled"].includes(status)) return res.status(400).send("status must be draft, published or cancelled.");
    const r = await pool.query(
      `UPDATE events SET status=$2 WHERE id=$1
       RETURNING id, club_id, title, start_at, status`, [id, status]
    );
    if (r.rows.length === 0) return res.status(404).send("Event not found.");
    console.log(`Admin ${req.user.userId} dogodek ${id} -> ${status}`);
    return res.status(200).json(r.rows[0]);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- finance ---
// GET /admin/api/finance?from=YYYY-MM-DD&to=YYYY-MM-DD
// Promet celotne platforme za admin panel: skupaj, po klubih, po dogodkih,
// po dnevih, zadnja naročila. Zneski v centih, EUR. "Prihodek Outlyja" =
// application_fee_cents (provizija PROVIZIJA_ODSTOTEK); "za klube" = bruto
// minus provizija minus vračila. Štejejo se samo plačana naročila
// (paid, partially_refunded); v testnem načinu (Stripe še ni) so to naročila
// s public_ref 'test_%' — panel to jasno označi.
admin.get("/finance", async (req, res) => {
  try {
    const dan = (v) => (typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v)) ? v : null;
    const do_ = dan(req.query.to) || new Date().toISOString().slice(0, 10);
    const od = dan(req.query.from) || new Date(Date.now() - 29 * 864e5).toISOString().slice(0, 10);
    if (od > do_) return res.status(400).send("from must be before to.");
    // Meji sta datuma; zgornja je vključujoča (do konca dneva).
    const p = [od, do_];
    const KJE = `o.status IN ('paid','partially_refunded') AND o.created_at >= $1::date AND o.created_at < ($2::date + INTERVAL '1 day')`;

    const [skupaj, poKlubih, poDogodkih, poDnevih, zadnja, vseh] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents),0)::int AS clubs_net_cents,
                COALESCE(SUM(o.quantity),0)::int AS tickets_sold,
                COUNT(*)::int AS orders,
                COUNT(DISTINCT o.user_id)::int AS buyers,
                COUNT(DISTINCT o.club_id)::int AS clubs_with_sales,
                COUNT(*) FILTER (WHERE o.stripe_payment_intent_id LIKE 'test_%')::int AS test_orders
         FROM orders o WHERE ${KJE}`, p),
      pool.query(
        `SELECT c.id, c.name, c.city, c.stripe_charges_enabled, c.stripe_payouts_enabled,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents),0)::int AS net_cents,
                COALESCE(SUM(o.quantity),0)::int AS tickets_sold,
                COUNT(o.id)::int AS orders
         FROM clubs c LEFT JOIN orders o ON o.club_id = c.id AND ${KJE}
         GROUP BY c.id ORDER BY gross_cents DESC, c.name`, p),
      pool.query(
        `SELECT e.id, e.title, e.start_at, e.status, e.ticket_price_cents, e.capacity, e.sold_count,
                c.name AS club_name,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.quantity),0)::int AS tickets_sold,
                (SELECT COUNT(*)::int FROM tickets t WHERE t.event_id = e.id AND t.status = 'used') AS checked_in
         FROM events e JOIN clubs c ON c.id = e.club_id
         LEFT JOIN orders o ON o.event_id = e.id AND ${KJE}
         GROUP BY e.id, c.name HAVING COUNT(o.id) > 0
         ORDER BY gross_cents DESC LIMIT 50`, p),
      pool.query(
        `SELECT to_char(d.dan, 'YYYY-MM-DD') AS day,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.quantity),0)::int AS tickets,
                COUNT(o.id)::int AS orders
         FROM generate_series($1::date, $2::date, '1 day') AS d(dan)
         LEFT JOIN orders o ON o.status IN ('paid','partially_refunded')
              AND o.created_at >= d.dan AND o.created_at < d.dan + INTERVAL '1 day'
         GROUP BY d.dan ORDER BY d.dan`, p),
      pool.query(
        `SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, c.name AS club_name, u.username AS buyer_username
         FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs c ON c.id = o.club_id
         LEFT JOIN users u ON u.id = o.user_id
         WHERE o.created_at >= $1::date AND o.created_at < ($2::date + INTERVAL '1 day')
         ORDER BY o.created_at DESC LIMIT 100`, p),
      pool.query(
        `SELECT COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.quantity),0)::int AS tickets_sold, COUNT(*)::int AS orders
         FROM orders o WHERE o.status IN ('paid','partially_refunded')`),
    ]);
    return res.json({
      mode: testniNacinPlacil() ? "test" : "live",
      fee_percent: PROVIZIJA_ODSTOTEK,
      from: od, to: do_,
      summary: skupaj.rows[0],
      all_time: vseh.rows[0],
      by_club: poKlubih.rows,
      by_event: poDogodkih.rows,
      by_day: poDnevih.rows,
      recent_orders: zadnja.rows,
    });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- varnostna kopija ---
// GET /admin/api/export — logični izvoz VSEH tabel v shemi public kot JSON
// (vrstice + trenutne vrednosti zaporedij), v enem posnetku (REPEATABLE READ),
// da so tabele med seboj skladne. Samo branje; nič se ne spremeni.
// Namenjeno varnostnim kopijam pred večjimi migracijami (Render brezplačni
// načrt kopij nima). Vsebuje tudi odtise gesel — datoteko hrani zasebno.
admin.get("/export", async (req, res) => {
  const c = await pool.connect();
  try {
    await c.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const t = await c.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name`
    );
    // DATE (OID 1082) v izvozu kot besedilo "YYYY-MM-DD": privzeti razčlenjevalnik
    // naredi Date v lokalnem času procesa in toISOString ga v pasu z odmikom
    // (Europe/Ljubljana) premakne za dan nazaj — date_of_birth bi po obnovi
    // pomenil drug rojstni dan (ujeto v _testi/test_obnova.js). Samo za ta klic,
    // odgovori API-ja se ne spremenijo.
    const tipiIzvoza = { getTypeParser: (oid, fmt) => (oid === 1082 ? (v) => v : pgTipi.getTypeParser(oid, fmt)) };
    const tables = {};
    for (const { table_name } of t.rows) {
      const r = await c.query({ text: `SELECT * FROM "${table_name.replace(/"/g, '""')}"`, types: tipiIzvoza });
      tables[table_name] = { count: r.rowCount, columns: r.fields.map((f) => f.name), rows: r.rows };
    }
    const s = await c.query(
      `SELECT sequencename AS name, last_value FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename`
    );
    const v = await c.query("SELECT version() AS version, NOW() AS now");
    await c.query("COMMIT");
    console.log(`Admin ${req.user.userId} izvoz baze (${t.rows.length} tabel)`);
    return res.json({
      exported_at: v.rows[0].now,
      postgres: v.rows[0].version,
      tables,
      sequences: s.rows,
    });
  } catch (e) {
    try { await c.query("ROLLBACK"); } catch (_) {}
    console.error(e);
    return res.status(500).send("Server error.");
  } finally {
    c.release();
  }
});

app.use("/admin/api", admin);

// ---------------------------
// VSTOPNICE: nakup, moje vstopnice, prodaja kluba, skeniranje
// ---------------------------
// Model je v migraciji 002 (orders, tickets, sprožilci za zalogo). Denar:
// prodajalec je KLUB, Outly je posrednik s provizijo (application_fee).
//
// NAČIN PLAČILA. Stripe Connect še ni vključen (rabi Stripe račun in odločitev
// o proviziji). Do takrat deluje TESTNI NAČIN: naročilo se takoj označi kot
// plačano, denar se ne premakne, naročilo dobi oznako test_ v
// stripe_payment_intent_id in odgovor nosi mode:"test". Testni način je
// dovoljen SAMO, dokler STRIPE_SECRET_KEY ni nastavljen (ali izrecno
// TEST_PLACILA=true). Ko pride Stripe, ta pot dobi PaymentIntent in webhook;
// vse ostalo (zaloga, vstopnice, QR, skener, prodaja) ostane.
const PROVIZIJA_ODSTOTEK = Number(process.env.PROVIZIJA_ODSTOTEK || 10); // ODLOČITEV MARTINA — začasno 10 %
const NAJVEC_NA_NAROCILO = 10;

function testniNacinPlacil() {
  if (process.env.TEST_PLACILA === "true") return true;
  return !process.env.STRIPE_SECRET_KEY;
}

// Koda QR: podpisan JSON, da jo skener preveri tudi brez omrežja (opomba 3 v 002).
// Skrivnost je QR_SECRET, sicer JWT_SECRET. Zamenjava skrivnosti razveljavi vse kode.
function qrSkrivnost() { return process.env.QR_SECRET || process.env.JWT_SECRET || ""; }
function podpisiQr(telo) {
  const b = Buffer.from(JSON.stringify(telo)).toString("base64url");
  const s = crypto.createHmac("sha256", qrSkrivnost()).update(b).digest("base64url").slice(0, 32);
  return `${b}.${s}`;
}
function preveriQr(koda) {
  if (typeof koda !== "string") return null;
  const deli = koda.trim().split(".");
  if (deli.length !== 2) return null;
  const [b, s] = deli;
  const pricakovan = crypto.createHmac("sha256", qrSkrivnost()).update(b).digest("base64url").slice(0, 32);
  if (s.length !== pricakovan.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(pricakovan))) return null;
  try { return JSON.parse(Buffer.from(b, "base64url").toString("utf8")); } catch (_) { return null; }
}
function qrVstopnice(t) {
  return podpisiQr({ v: 1, t: t.serial, e: t.event_id, i: Math.floor(new Date(t.created_at).getTime() / 1000) });
}
function javnaRef() {
  // 8 znakov brez zamenljivih (0/O, 1/I): OUT-7K3M9QPX
  const abc = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  let s = ""; const b = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) s += abc[b[i] % abc.length];
  return "OUT-" + s;
}

const STOLPCI_NAROCILA = `o.id, o.public_ref, o.event_id, o.club_id, o.quantity, o.unit_price_cents, o.total_cents,
  o.currency, o.application_fee_cents, o.status, o.buyer_email, o.created_at, o.paid_at, o.cancelled_at,
  o.refunded_cents, (o.stripe_payment_intent_id LIKE 'test_%') AS is_test`;
const STOLPCI_VSTOPNICE = `t.id, t.order_id, t.event_id, t.serial, t.status, t.used_at, t.created_at, t.holder_user_id`;
// Imetnik vstopnice: kdor jo je prejel s prenosom, sicer kupec (008).
const IMETNIK = `COALESCE(t.holder_user_id, o.user_id)`;
const STOLPCI_IMETNIKA = `${IMETNIK} AS holder_id, hu.username AS holder_username, hu.email AS holder_email,
  (t.holder_user_id IS NOT NULL AND t.holder_user_id IS DISTINCT FROM o.user_id) AS transferred`;
const JOIN_IMETNIK = `LEFT JOIN users hu ON hu.id = ${IMETNIK}`;

// db: neobvezen odjemalec iz pool.connect(); klicatelj, ki ga že drži, MORA
// poizvedovati prek njega, ne prek pool (glej opombo pri POST /events/:id/orders).
async function vstopniceNarocil(idsNarocil, db = pool) {
  if (!idsNarocil.length) return {};
  const r = await db.query(
    `SELECT ${STOLPCI_VSTOPNICE}, ${STOLPCI_IMETNIKA} FROM tickets t JOIN orders o ON o.id = t.order_id ${JOIN_IMETNIK}
     WHERE t.order_id = ANY($1::bigint[]) ORDER BY t.id`, [idsNarocil]
  );
  const po = {};
  // Kupec vidi QR samo za vstopnice, ki jih se ima; prenesene kaze brez kode.
  for (const t of r.rows) (po[t.order_id] ||= []).push({ ...t, qr: t.transferred ? null : qrVstopnice(t) });
  return po;
}

// POST /events/:id/orders — nakup. Telo: { quantity }.
app.post("/events/:id/orders", requireAuth, omeji({ kljuc: "nakup", najvec: 20, oknoSekund: 3600 }), async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid event id.");
  const q = Number((req.body || {}).quantity ?? 1);
  if (!Number.isInteger(q) || q < 1 || q > NAJVEC_NA_NAROCILO) {
    return res.status(400).send(`quantity must be an integer between 1 and ${NAJVEC_NA_NAROCILO}.`);
  }
  if (!testniNacinPlacil()) {
    // Stripe je nastavljen, testna pot je izklopljena; prava pot še ni napisana.
    return res.status(503).send("Payments are not available yet.");
  }

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const er = await c.query(
      `SELECT e.id, e.club_id, e.title, e.status, e.start_at, e.min_age, e.ticket_price_cents, e.currency,
              e.capacity, e.sold_count, e.sales_open_at, e.sales_close_at, e.vat_rate, c.hidden
       FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1`, [id]
    );
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    const e = er.rows[0];
    if (e.status !== "published" || e.hidden) { await c.query("ROLLBACK"); return res.status(409).send("Event is not on sale."); }
    if (e.ticket_price_cents === null) { await c.query("ROLLBACK"); return res.status(409).send("This event has no tickets on Outly."); }
    const zdaj = Date.now();
    if (new Date(e.start_at).getTime() < zdaj) { await c.query("ROLLBACK"); return res.status(409).send("Event has already started."); }
    if (e.sales_open_at && new Date(e.sales_open_at).getTime() > zdaj) { await c.query("ROLLBACK"); return res.status(409).send("Ticket sales have not opened yet."); }
    if (e.sales_close_at && new Date(e.sales_close_at).getTime() < zdaj) { await c.query("ROLLBACK"); return res.status(409).send("Ticket sales are closed."); }
    if (e.capacity !== null && e.sold_count + q > e.capacity) {
      await c.query("ROLLBACK"); return res.status(409).send(`Only ${Math.max(0, e.capacity - e.sold_count)} tickets left.`);
    }

    // Starost: datum rojstva je izjava uporabnika (glej 003), a 17-letniku
    // vstopnice za 18+ ne prodamo. Brez datuma rojstva nakup za 18+ ni mogoč.
    const ur = await c.query("SELECT email, starost(date_of_birth) AS leta FROM users WHERE id=$1", [req.user.userId]);
    if (ur.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("User not found."); }
    const u = ur.rows[0];
    if (e.min_age > 0) {
      if (u.leta === null) { await c.query("ROLLBACK"); return res.status(403).send("Add your date of birth to buy tickets for this event."); }
      if (u.leta < e.min_age) { await c.query("ROLLBACK"); return res.status(403).send(`You must be at least ${e.min_age} to buy tickets for this event.`); }
    }

    const skupaj = e.ticket_price_cents * q;
    const provizija = Math.round(skupaj * PROVIZIJA_ODSTOTEK / 100);
    const ref = javnaRef();
    const pi = "test_" + crypto.randomUUID();

    // Sprožilec orders_rezerviraj zaklene dogodek in preveri zalogo še enkrat.
    const or = await c.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency,
                           application_fee_cents, vat_rate, status, stripe_payment_intent_id, buyer_email, paid_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'paid',$11,$12,NOW()) RETURNING id`,
      [ref, req.user.userId, e.id, e.club_id, q, e.ticket_price_cents, skupaj, e.currency, provizija, e.vat_rate, pi, u.email]
    );
    const oid = or.rows[0].id;
    await c.query(
      `INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [oid, e.id, q]
    );
    await c.query("COMMIT");

    // POZOR: tu še držimo odjemalca c. Branje po COMMIT-u gre prek c, NE prek
    // pool: pri 10+ hkratnih nakupih (pool ima privzeto 10 povezav) bi vsak
    // zahtevek držal svojo povezavo in čakal na enajsto -> celoten backend
    // obvisi, dokler ga Render ne zažene znova (ugotovljeno s testom sočasnosti).
    const nr = await c.query(`SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, e.start_at, e.poster_url, cl.name AS club_name
       FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = o.club_id WHERE o.id = $1`, [oid]);
    const vst = await vstopniceNarocil([oid], c);
    console.log(`Nakup (test): naročilo ${ref}, uporabnik ${req.user.userId}, dogodek ${e.id}, ${q}x ${e.ticket_price_cents} c`);
    return res.status(201).json({ mode: "test", order: nr.rows[0], tickets: vst[oid] || [] });
  } catch (err) {
    await c.query("ROLLBACK").catch(() => {});
    // Sprožilec: "Ni dovolj vstopnic" pride kot check_violation.
    if (err && err.code === "23514") return res.status(409).send(/Ni dovolj/.test(err.message) ? "Not enough tickets left." : "Order rejected: " + (err.constraint || err.message));
    console.error(err);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

// GET /me/orders — moja naročila z vstopnicami.
app.get("/me/orders", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, e.start_at, e.poster_url, cl.name AS club_name
       FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = o.club_id
       WHERE o.user_id = $1 ORDER BY o.created_at DESC LIMIT 100`, [req.user.userId]
    );
    const vst = await vstopniceNarocil(r.rows.map(o => o.id));
    return res.json(r.rows.map(o => ({ ...o, tickets: vst[o.id] || [] })));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /me/tickets — moje vstopnice (plačana naročila), prihajajoče najprej.
// ---------------------------
// PRILJUBLJENI DOGODKI (migracija 012)
// ---------------------------
// GET /me/favorites -> { ids: [..], events: [..] } (dogodki, ki še obstajajo;
// odpovedani/osnutki so izpuščeni iz seznama, id-ji pa ostanejo, da srček v
// aplikaciji ne "pade").
app.get("/me/favorites", requireAuth, async (req, res) => {
  try {
    const [ids, dogodki] = await Promise.all([
      pool.query("SELECT event_id FROM event_favorites WHERE user_id=$1 ORDER BY created_at DESC", [req.user.userId]),
      pool.query(
        `SELECT x.*, f.created_at AS favorited_at
         FROM event_favorites f
         JOIN (SELECT ${STOLPCI_DOGODKA} FROM events) x ON x.id = f.event_id
         WHERE f.user_id = $1 AND x.status = 'published'
           AND x.club_id NOT IN (SELECT id FROM clubs WHERE hidden)
         ORDER BY x.start_at ASC`,
        [req.user.userId]),
    ]);
    return res.json({ ids: ids.rows.map(r => r.event_id), events: dogodki.rows });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// PUT /me/favorites/:eventId — označi (idempotentno). 404, če dogodka ni.
app.put("/me/favorites/:eventId", requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.eventId, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).send("Invalid event id.");
    const r = await pool.query(
      `INSERT INTO event_favorites (user_id, event_id)
       SELECT $1, e.id FROM events e WHERE e.id = $2
       ON CONFLICT DO NOTHING RETURNING event_id`, [req.user.userId, id]);
    const obstaja = r.rows.length || (await pool.query("SELECT 1 FROM events WHERE id=$1", [id])).rows.length;
    if (!obstaja) return res.status(404).send("Event not found.");
    return res.status(200).json({ event_id: id, favorite: true });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /me/favorites/:eventId — odznači (idempotentno).
app.delete("/me/favorites/:eventId", requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.eventId, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).send("Invalid event id.");
    await pool.query("DELETE FROM event_favorites WHERE user_id=$1 AND event_id=$2", [req.user.userId, id]);
    return res.status(200).json({ event_id: id, favorite: false });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

app.get("/me/tickets", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT ${STOLPCI_VSTOPNICE}, o.public_ref, o.status AS order_status,
              e.title AS event_title, e.start_at, e.end_at, e.poster_url, e.min_age,
              cl.id AS club_id, cl.name AS club_name, cl.address, cl.city, cl.logo_url,
              ${STOLPCI_IMETNIKA}, bu.username AS buyer_username,
              (t.status = 'valid' AND e.start_at > NOW()) AS transferable
       FROM tickets t JOIN orders o ON o.id = t.order_id
       JOIN events e ON e.id = t.event_id JOIN clubs cl ON cl.id = e.club_id
       ${JOIN_IMETNIK} LEFT JOIN users bu ON bu.id = o.user_id
       WHERE t.id IN (
         -- Dva indeksirana vira namesto COALESCE(...) = $1, ki je bral VSE
         -- vstopnice in naročila (pri 120.000 vstopnicah 30 ms, raste linearno).
         SELECT id FROM tickets WHERE holder_user_id = $1
         UNION ALL
         SELECT t2.id FROM orders o2 JOIN tickets t2 ON t2.order_id = o2.id
          WHERE o2.user_id = $1 AND t2.holder_user_id IS NULL
       ) AND o.status IN ('paid','partially_refunded')
       ORDER BY (e.start_at >= NOW()) DESC, e.start_at ASC, t.id ASC LIMIT 200`, [req.user.userId]
    );
    return res.json(r.rows.map(t => ({ ...t, qr: qrVstopnice(t) })));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- poslovni del: prodaja ---
// Klub iz requireClub (lastnik ali član ekipe). Admin brez kluba -> null -> 404.
async function mojKlubId(req) {
  return req.klub ? req.klub.clubId : null;
}

// GET /business/sales — povzetek prodaje lastnega kluba, po dogodkih, zadnja naročila.
app.get("/business/sales", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const [povzetek, poDogodkih, zadnja, poDnevih] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents),0)::int AS net_cents,
                COALESCE(SUM(o.quantity),0)::int AS tickets_sold,
                COUNT(*)::int AS orders,
                COUNT(DISTINCT o.user_id)::int AS buyers,
                COALESCE(SUM(o.total_cents) FILTER (WHERE o.created_at > NOW() - INTERVAL '7 days'),0)::int AS gross_7d_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.created_at > NOW() - INTERVAL '7 days'),0)::int AS tickets_7d
         FROM orders o WHERE o.club_id = $1 AND o.status IN ('paid','partially_refunded')`, [klub]),
      pool.query(
        `SELECT e.id, e.title, e.start_at, e.poster_url, e.status, e.ticket_price_cents, e.capacity, e.sold_count,
                COALESCE(SUM(o.total_cents) FILTER (WHERE o.status IN ('paid','partially_refunded')),0)::int AS gross_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.status IN ('paid','partially_refunded')),0)::int AS tickets_sold,
                (SELECT COUNT(*)::int FROM tickets t WHERE t.event_id = e.id AND t.status = 'used') AS checked_in
         FROM events e LEFT JOIN orders o ON o.event_id = e.id
         WHERE e.club_id = $1 GROUP BY e.id ORDER BY e.start_at DESC LIMIT 100`, [klub]),
      pool.query(
        `SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, u.username AS buyer_username
         FROM orders o JOIN events e ON e.id = o.event_id LEFT JOIN users u ON u.id = o.user_id
         WHERE o.club_id = $1 ORDER BY o.created_at DESC LIMIT 30`, [klub]),
      // Zadnjih 14 dni po dnevih (tudi dnevi brez prodaje), za graf v nadzorni plosci.
      pool.query(
        `SELECT to_char(d.dan, 'YYYY-MM-DD') AS day,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.quantity),0)::int AS tickets
         FROM generate_series((CURRENT_DATE - INTERVAL '13 days')::date, CURRENT_DATE, '1 day') AS d(dan)
         LEFT JOIN orders o ON o.club_id = $1 AND o.status IN ('paid','partially_refunded')
              AND o.created_at >= d.dan AND o.created_at < d.dan + INTERVAL '1 day'
         GROUP BY d.dan ORDER BY d.dan`, [klub]),
    ]);
    return res.json({
      mode: testniNacinPlacil() ? "test" : "live",
      fee_percent: PROVIZIJA_ODSTOTEK,
      summary: povzetek.rows[0],
      events: poDogodkih.rows,
      recent_orders: zadnja.rows,
      sales_by_day: poDnevih.rows,
    });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /business/events/:id/tickets — vstopnice dogodka (za vrata: kdo je prišel).
app.get("/business/events/:id/tickets", requireAuth, requireClub(), async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const r = await pool.query(
      `SELECT ${STOLPCI_VSTOPNICE}, o.public_ref, o.buyer_email, u.username AS buyer_username, ${STOLPCI_IMETNIKA}
       FROM tickets t JOIN orders o ON o.id = t.order_id JOIN events e ON e.id = t.event_id
       LEFT JOIN users u ON u.id = o.user_id ${JOIN_IMETNIK}
       WHERE t.event_id = $1 AND e.club_id = $2 ORDER BY t.id LIMIT 1000`, [id, klub]
    );
    return res.json(r.rows.map(t => ({ ...t, qr: qrVstopnice(t) })));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /tickets/:id/transfer — prenos vstopnice prijatelju. Telo: { email }.
// Prenese lahko samo trenutni imetnik; samo veljavno vstopnico pred zacetkom dogodka;
// prejemnik mora imeti Outly racun in izpolnjevati min_age. Serial se zamenja ->
// star QR (posnetek zaslona pri posiljatelju) ne velja vec. Narocilo ostane kupcu (008).
app.post("/tickets/:id/transfer", requireAuth, omeji({ kljuc: "prenos", najvec: 30, oknoSekund: 3600 }), async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid ticket id.");
  // Prejemnik: { user_id } prijatelja (izbira iz seznama, migracija 016) ALI { email } kot doslej.
  // Po id sme samo prijatelju — sicer bi se dalo z ugibanjem id-jev posiljati vstopnice
  // (in izvedeti uporabniska imena) neznancem.
  const b0 = req.body || {};
  const prejemnikId = b0.user_id !== undefined ? celoId(b0.user_id) : null;
  const email = prejemnikId ? "" : String(b0.email || "").trim().toLowerCase();
  if (b0.user_id !== undefined && !prejemnikId) return res.status(400).send("Invalid user_id.");
  if (!prejemnikId && (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).send("A valid email is required.");
  if (prejemnikId && !(await staPrijatelja(req.user.userId, prejemnikId))) return res.status(404).send("You can only send a ticket by user to one of your friends.");

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const tr = await c.query(
      `SELECT t.id, t.serial, t.status, t.event_id, ${IMETNIK} AS holder_id, o.status AS order_status,
              e.title AS event_title, e.start_at, e.min_age
       FROM tickets t JOIN orders o ON o.id = t.order_id JOIN events e ON e.id = t.event_id
       WHERE t.id = $1 FOR UPDATE OF t`, [id]
    );
    if (tr.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Ticket not found."); }
    const t = tr.rows[0];
    // Tuja vstopnica: 404, ne 403 — ne razkrivamo, da obstaja.
    if (Number(t.holder_id) !== Number(req.user.userId)) { await c.query("ROLLBACK"); return res.status(404).send("Ticket not found."); }
    if (!["paid", "partially_refunded"].includes(t.order_status)) { await c.query("ROLLBACK"); return res.status(409).send("Order is not paid."); }
    if (t.status === "used") { await c.query("ROLLBACK"); return res.status(409).send("Ticket was already used."); }
    if (t.status !== "valid") { await c.query("ROLLBACK"); return res.status(409).send(`Ticket is ${t.status}.`); }
    if (new Date(t.start_at).getTime() <= Date.now()) { await c.query("ROLLBACK"); return res.status(409).send("Event has already started."); }

    const pr = prejemnikId
      ? await c.query("SELECT id, email, username, email_verified, starost(date_of_birth) AS leta FROM users WHERE id = $1", [prejemnikId])
      : await c.query("SELECT id, email, username, email_verified, starost(date_of_birth) AS leta FROM users WHERE LOWER(email) = $1", [email]);
    if (pr.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("No Outly account with this email. Ask your friend to sign up first."); }
    const p = pr.rows[0];
    if (Number(p.id) === Number(req.user.userId)) { await c.query("ROLLBACK"); return res.status(400).send("You already hold this ticket."); }
    if (!p.email_verified) { await c.query("ROLLBACK"); return res.status(409).send("Your friend's account is not verified yet."); }
    if (t.min_age > 0) {
      if (p.leta === null) { await c.query("ROLLBACK"); return res.status(403).send("Your friend must add a date of birth before receiving a ticket for this event."); }
      if (p.leta < t.min_age) { await c.query("ROLLBACK"); return res.status(403).send(`Your friend must be at least ${t.min_age} for this event.`); }
    }

    const u = await c.query(
      `UPDATE tickets SET holder_user_id = $2, serial = gen_random_uuid() WHERE id = $1 AND status = 'valid'
       RETURNING id, order_id, event_id, serial, status, used_at, created_at, holder_user_id`, [t.id, p.id]
    );
    if (u.rows.length === 0) { await c.query("ROLLBACK"); return res.status(409).send("Ticket is no longer valid."); }
    await c.query(
      `INSERT INTO ticket_transfers (ticket_id, from_user_id, to_user_id, to_email, old_serial, new_serial) VALUES ($1,$2,$3,$4,$5,$6)`,
      [t.id, req.user.userId, p.id, p.email, t.serial, u.rows[0].serial]
    );
    await c.query("COMMIT");
    console.log(`Prenos vstopnice ${t.id}: uporabnik ${req.user.userId} -> ${p.id} (dogodek ${t.event_id})`);
    // Posiljatelj nove kode ne dobi — vstopnica ni vec njegova.
    return res.status(200).json({
      result: "ok", message: `Ticket sent to ${p.username || p.email}.`,
      ticket: { id: u.rows[0].id, event_id: t.event_id, event_title: t.event_title, status: u.rows[0].status,
                holder_username: p.username, holder_email: p.email, transferred: true }
    });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    console.error(e); return res.status(500).send("Server error.");
  } finally { c.release(); }
});

// POST /business/tickets/scan — skener na vratih. Telo: { qr } (ali { serial } za ročni vnos).
// Preveri podpis, lastništvo, stanje; vstopnico označi kot uporabljeno. Ponovni sken -> 409.
app.post("/business/tickets/scan", requireAuth, requireClub(), async (req, res) => {
  try {
    const b = req.body || {};
    let serial = null, ev = null;
    if (b.qr !== undefined) {
      const v = preveriQr(b.qr);
      if (!v || !v.t) return res.status(400).json({ result: "invalid", message: "QR code is not valid (bad signature)." });
      serial = String(v.t); ev = v.e;
    } else if (typeof b.serial === "string") {
      serial = b.serial.trim();
    } else return res.status(400).send("qr or serial is required.");
    if (!/^[0-9a-f-]{36}$/i.test(serial)) return res.status(400).json({ result: "invalid", message: "Ticket code is not valid." });

    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");

    const r = await pool.query(
      `SELECT ${STOLPCI_VSTOPNICE}, e.club_id, e.title AS event_title, e.start_at, o.status AS order_status, o.public_ref, o.buyer_email,
              ${STOLPCI_IMETNIKA}
       FROM tickets t JOIN events e ON e.id = t.event_id JOIN orders o ON o.id = t.order_id ${JOIN_IMETNIK} WHERE t.serial = $1`, [serial]
    );
    if (r.rows.length === 0) return res.status(404).json({ result: "unknown", message: "Ticket not found." });
    const t = r.rows[0];
    if (t.club_id !== klub) return res.status(403).json({ result: "wrong_club", message: "This ticket is for another club's event." });
    if (ev !== undefined && ev !== null && Number(ev) !== t.event_id) return res.status(400).json({ result: "invalid", message: "QR code does not match the ticket." });
    if (!["paid", "partially_refunded"].includes(t.order_status)) return res.status(409).json({ result: "unpaid", message: "Order is not paid." });
    if (t.status === "used") return res.status(409).json({ result: "already_used", message: "Ticket was already scanned.", used_at: t.used_at, ticket: t });
    if (t.status !== "valid") return res.status(409).json({ result: t.status, message: `Ticket is ${t.status}.`, ticket: t });

    // Pogoj serial=$4: če je bila vstopnica med branjem zgoraj in tem UPDATE-om
    // prenesena prijatelju (prenos ji da NOV serial), stara koda ne sme več
    // veljati — sicer bi pošiljatelj vstopil s staro kodo, prejemnik pa bi
    // dobil že porabljeno vstopnico (ugotovljeno s testom sočasnosti).
    const u = await pool.query(
      `UPDATE tickets SET status='used', used_at=NOW(), used_by_user_id=$2, scan_device=$3
       WHERE id=$1 AND status='valid' AND serial=$4 RETURNING id, serial, status, used_at`,
      [t.id, req.user.userId, String(req.headers["user-agent"] || "").slice(0, 100), serial]
    );
    if (u.rows.length === 0) {
      const z = await pool.query(`SELECT status, serial FROM tickets WHERE id=$1`, [t.id]);
      const s = z.rows[0];
      if (s && s.serial !== serial) return res.status(409).json({ result: "transferred", message: "This ticket was passed on to someone else. Ask them to show their new code." });
      return res.status(409).json({ result: "already_used", message: "Ticket was already scanned." });
    }
    return res.status(200).json({ result: "ok", message: "Welcome in.", ticket: { ...t, ...u.rows[0] } });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// ---------------------------
// EKIPA KLUBA (migracija 009)
// ---------------------------
// Lastnik vabi managerje in vratarje; manager sme vabiti in odstranjevati
// samo vratarje. Od migracije 013 je dodajanje VABILO: uporabnik ga sprejme ali
// zavrne v aplikaciji (My clubs -> zvonec), član nastane ob sprejemu. Povabljeni
// mora že imeti Outly račun (po e-naslovu). Sodelavec je lahko v največ eni
// ekipi in lastnik kluba ne more biti hkrati član druge.
const VLOGE_EKIPE = ["manager", "doorman"];

async function seznamEkipe(clubId) {
  const r = await pool.query(
    `SELECT * FROM (
       SELECT u.id AS user_id, u.username, u.email, u.avatar_url, 'owner' AS role, c.created_at, NULL::int AS invited_by_user_id
         FROM clubs c JOIN users u ON u.id = c.owner_user_id WHERE c.id = $1
       UNION ALL
       SELECT u.id, u.username, u.email, u.avatar_url, m.role, m.created_at, m.invited_by_user_id
         FROM club_members m JOIN users u ON u.id = m.user_id WHERE m.club_id = $1
     ) e ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END, created_at`,
    [clubId]
  );
  return r.rows;
}

// Mail sodelavcu ob VABILU (migracija 013): vabilo sprejme ali zavrne v aplikaciji
// (Profile -> My clubs -> zvonec). Prej je bil dodan neposredno.
async function posljiVabiloEkipi(toEmail, clubName, role) {
  if (!resend) return;
  const from = process.env.EMAIL_FROM || "onboarding@resend.dev";
  const appName = process.env.APP_NAME || "Outly";
  const vloga = role === "manager" ? "manager" : "door staff";
  try {
    const r = await resend.emails.send({
      from, to: toEmail,
      subject: `${clubName} invited you to their team on ${appName}`,
      html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – Club team</h2>
      <p><b>${clubName}</b> has invited you to work with them as <b>${vloga}</b>.</p>
      <p>Open the ${appName} app, go to <b>Profile → My clubs</b> and tap the bell to accept or reject the invitation.</p>
      <p>If you don't know this club, simply reject the invitation or ignore this email.</p>
    </div>`,
    });
    if (r && r.error) console.error("Resend napaka (vabilo):", JSON.stringify(r.error));
  } catch (e) { console.error("Resend napaka (vabilo):", e); }
}

// Čakajoča vabila kluba (za GET /business/team).
async function seznamVabilKluba(clubId) {
  const r = await pool.query(
    `SELECT i.id, i.user_id, u.username, u.email, u.avatar_url, i.role, i.created_at, i.invited_by_user_id
       FROM club_invites i JOIN users u ON u.id = i.user_id
      WHERE i.club_id = $1 AND i.status = 'pending'
      ORDER BY i.created_at`,
    [clubId]
  );
  return r.rows;
}

async function odgovorEkipe(req, klub) {
  return { my_role: req.klub.role, members: await seznamEkipe(klub), invites: await seznamVabilKluba(klub) };
}

// GET /business/team — lastnik + člani + čakajoča vabila. Vratar ekipe ne vidi.
app.get("/business/team", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    return res.json(await odgovorEkipe(req, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /business/team — telo: { email, role }. Od migracije 013 ustvari VABILO
// (status pending); član nastane šele, ko uporabnik vabilo sprejme
// (POST /me/invites/:id/accept). Vrne posodobljen seznam (members + invites).
app.post("/business/team", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const b = req.body || {};
    const email = typeof b.email === "string" ? b.email.trim().toLowerCase() : "";
    const role = typeof b.role === "string" ? b.role.trim().toLowerCase() : "";
    if (!email || !email.includes("@")) return res.status(400).send("Valid email is required.");
    if (!VLOGE_EKIPE.includes(role)) return res.status(400).send("role must be manager or doorman.");
    if (req.klub.role === "manager" && role !== "doorman") {
      return res.status(403).send("Only the club owner can invite managers.");
    }

    const u = await pool.query("SELECT id, username, email FROM users WHERE LOWER(email)=$1", [email]);
    if (u.rows.length === 0) {
      return res.status(404).json({ error: "no_account", message: "No Outly account with this email. Ask them to sign up first." });
    }
    const clan = u.rows[0];
    if (Number(clan.id) === Number(req.user.userId)) return res.status(400).send("You are already in this team.");

    const jeLastnik = await pool.query("SELECT id FROM clubs WHERE owner_user_id=$1 LIMIT 1", [clan.id]);
    if (jeLastnik.rows.length) {
      const svoj = Number(jeLastnik.rows[0].id) === Number(klub);
      return res.status(409).json({ error: "is_owner", message: svoj ? "This user owns the club." : "This user already owns another club." });
    }
    const ze = await pool.query("SELECT club_id, role FROM club_members WHERE user_id=$1", [clan.id]);
    if (ze.rows.length) {
      const tu = Number(ze.rows[0].club_id) === Number(klub);
      return res.status(409).json({ error: "already_member", message: tu ? `Already in the team as ${ze.rows[0].role}.` : "This user is already in another club's team." });
    }
    const caka = await pool.query("SELECT id FROM club_invites WHERE club_id=$1 AND user_id=$2 AND status='pending'", [klub, clan.id]);
    if (caka.rows.length) {
      return res.status(409).json({ error: "already_invited", message: "This user already has a pending invitation from your club." });
    }

    await pool.query(
      "INSERT INTO club_invites (club_id, user_id, role, invited_by_user_id) VALUES ($1,$2,$3,$4)",
      [klub, clan.id, role, req.user.userId]
    );
    const ime = await pool.query("SELECT name FROM clubs WHERE id=$1", [klub]);
    posljiVabiloEkipi(clan.email, ime.rows[0] ? ime.rows[0].name : "A club", role); // brez await: mail ne sme zadrževati odgovora
    return res.status(201).json(await odgovorEkipe(req, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /business/team/invites/:id — prekliče čakajoče vabilo. Manager sme samo vratarje.
// (Definirano PRED /business/team/:userId; poti se ne prekrivata, ker ima ta dodaten del.)
app.delete("/business/team/invites/:id", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid invite id.");
    const i = await pool.query("SELECT role FROM club_invites WHERE id=$1 AND club_id=$2 AND status='pending'", [id, klub]);
    if (i.rows.length === 0) return res.status(404).send("Invitation not found.");
    if (req.klub.role === "manager" && i.rows[0].role !== "doorman") {
      return res.status(403).send("Only the club owner can cancel manager invitations.");
    }
    await pool.query("UPDATE club_invites SET status='cancelled', responded_at=NOW() WHERE id=$1", [id]);
    return res.json(await odgovorEkipe(req, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// ---------------------------
// MOJA VABILA (uporabnik; migracija 013)
// ---------------------------
async function mojaVabila(userId) {
  const r = await pool.query(
    `SELECT i.id, i.club_id, c.name AS club_name, c.logo_url AS club_logo_url, c.city AS club_city,
            i.role, i.created_at, u.username AS invited_by_username
       FROM club_invites i
       JOIN clubs c ON c.id = i.club_id
       LEFT JOIN users u ON u.id = i.invited_by_user_id
      WHERE i.user_id = $1 AND i.status = 'pending'
      ORDER BY i.created_at DESC`,
    [userId]
  );
  return r.rows;
}

// GET /me/invites -> { invites: [...] } (samo čakajoča).
app.get("/me/invites", requireAuth, async (req, res) => {
  try {
    return res.json({ invites: await mojaVabila(req.user.userId) });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /me/invites/:id/accept -> { club: {id, name, logo_url}, role, invites: [...] }.
// V eni transakciji: vabilo mora biti čakajoče in moje; uporabnik ne sme biti
// lastnik kluba ali že član (največ ena ekipa); ostala čakajoča vabila -> declined.
app.post("/me/invites/:id/accept", requireAuth, async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid invite id.");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const i = await client.query(
      "SELECT i.id, i.club_id, i.role, i.invited_by_user_id, c.name, c.logo_url FROM club_invites i JOIN clubs c ON c.id=i.club_id WHERE i.id=$1 AND i.user_id=$2 AND i.status='pending' FOR UPDATE OF i",
      [id, req.user.userId]
    );
    if (i.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).send("Invitation not found or no longer pending."); }
    const v = i.rows[0];
    const lastnik = await client.query("SELECT id FROM clubs WHERE owner_user_id=$1 LIMIT 1", [req.user.userId]);
    if (lastnik.rows.length) { await client.query("ROLLBACK"); return res.status(409).json({ error: "is_owner", message: "You own a club and can't join another team." }); }
    const clan = await client.query("SELECT club_id FROM club_members WHERE user_id=$1", [req.user.userId]);
    if (clan.rows.length) { await client.query("ROLLBACK"); return res.status(409).json({ error: "already_member", message: "You are already in a club team. Leave it first." }); }

    await client.query(
      "INSERT INTO club_members (club_id, user_id, role, invited_by_user_id) VALUES ($1,$2,$3,$4)",
      [v.club_id, req.user.userId, v.role, v.invited_by_user_id]
    );
    await client.query("UPDATE club_invites SET status='accepted', responded_at=NOW() WHERE id=$1", [id]);
    await client.query("UPDATE club_invites SET status='declined', responded_at=NOW() WHERE user_id=$1 AND status='pending'", [req.user.userId]);
    await client.query("COMMIT");
    return res.json({ club: { id: v.club_id, name: v.name, logo_url: v.logo_url }, role: v.role, invites: [] });
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch (_) {}
    console.error(e); return res.status(500).send("Server error.");
  } finally { client.release(); }
});

// POST /me/invites/:id/decline -> { invites: [...] }.
app.post("/me/invites/:id/decline", requireAuth, async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid invite id.");
    const r = await pool.query(
      "UPDATE club_invites SET status='declined', responded_at=NOW() WHERE id=$1 AND user_id=$2 AND status='pending' RETURNING id",
      [id, req.user.userId]
    );
    if (r.rows.length === 0) return res.status(404).send("Invitation not found or no longer pending.");
    return res.json({ invites: await mojaVabila(req.user.userId) });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// ---------------------------
// PRIJATELJI (migracija 016)
// ---------------------------
// "My friends" v profilu, prošnje v obvestilih, "Your friends' plans" na domačem
// zaslonu, prenos vstopnice prijatelju z izbiro iz seznama. Prijateljstvo je
// simetrično in shranjeno enkrat (user_a < user_b). O tujem uporabniku se
// razkrije SAMO id, username in avatar_url — nikoli e-naslov, telefon, rojstvo.
const POLJA_PRIJATELJA = "u.id, u.username, u.avatar_url";

async function staPrijatelja(a, b) {
  const r = await pool.query(
    "SELECT 1 FROM friendships WHERE user_a = LEAST($1::int,$2::int) AND user_b = GREATEST($1::int,$2::int)", [a, b]
  );
  return r.rows.length > 0;
}

async function mojiPrijatelji(userId) {
  const r = await pool.query(
    `SELECT ${POLJA_PRIJATELJA}, f.created_at AS since
       FROM friendships f
       JOIN users u ON u.id = CASE WHEN f.user_a = $1 THEN f.user_b ELSE f.user_a END
      WHERE f.user_a = $1 OR f.user_b = $1
      ORDER BY LOWER(u.username)`, [userId]
  );
  return r.rows;
}

async function mojeProsnje(userId) {
  const r = await pool.query(
    `SELECT r.id, r.from_user_id, r.to_user_id, r.created_at,
            u.id AS other_id, u.username AS other_username, u.avatar_url AS other_avatar_url
       FROM friend_requests r
       JOIN users u ON u.id = CASE WHEN r.from_user_id = $1 THEN r.to_user_id ELSE r.from_user_id END
      WHERE (r.from_user_id = $1 OR r.to_user_id = $1) AND r.status = 'pending'
      ORDER BY r.created_at DESC`, [userId]
  );
  const oblikuj = (x) => ({ id: x.id, created_at: x.created_at, user: { id: x.other_id, username: x.other_username, avatar_url: x.other_avatar_url } });
  return {
    incoming: r.rows.filter(x => Number(x.to_user_id) === Number(userId)).map(oblikuj),
    outgoing: r.rows.filter(x => Number(x.from_user_id) === Number(userId)).map(oblikuj),
  };
}

// GET /users/search?q=ime — iskanje po uporabniškem imenu (predpona), samo prijavljeni,
// največ 10 zadetkov, brez sebe, samo potrjeni računi. Vrne id, username, avatar_url in
// relation: 'none' | 'friends' | 'request_sent' | 'request_received'. Omejeno, da se
// imenik ne da izluščiti z avtomatskim iskanjem.
app.get("/users/search", requireAuth, omeji({ kljuc: "iskanje", najvec: 120, oknoSekund: 3600 }), async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (q.length < 2 || q.length > 20 || !/^[a-zA-Z0-9_]+$/.test(q)) return res.status(400).send("q must be 2-20 characters: letters, numbers, underscore.");
    // '_' je v LIKE nadomestni znak -> ubežimo ga, da "an_" ne najde "ana".
    const vzorec = q.replace(/_/g, "\\_");
    const r = await pool.query(
      `SELECT ${POLJA_PRIJATELJA},
              EXISTS (SELECT 1 FROM friendships f WHERE f.user_a = LEAST(u.id,$2::int) AND f.user_b = GREATEST(u.id,$2::int)) AS is_friend,
              (SELECT CASE WHEN r.from_user_id = $2 THEN 'request_sent' ELSE 'request_received' END
                 FROM friend_requests r
                WHERE r.status = 'pending'
                  AND LEAST(r.from_user_id, r.to_user_id) = LEAST(u.id,$2::int)
                  AND GREATEST(r.from_user_id, r.to_user_id) = GREATEST(u.id,$2::int)
                LIMIT 1) AS req_relation
         FROM users u
        WHERE u.username ILIKE $1 || '%' ESCAPE '\\' AND u.id <> $2 AND u.email_verified
        ORDER BY (LOWER(u.username) = LOWER($1)) DESC, LOWER(u.username)
        LIMIT 10`,
      [vzorec, req.user.userId]
    );
    return res.json({ users: r.rows.map(x => ({
      id: x.id, username: x.username, avatar_url: x.avatar_url,
      relation: x.is_friend ? "friends" : (x.req_relation || "none"),
    })) });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /me/friends -> { friends: [...], requests_in: [...], requests_out: [...] }
app.get("/me/friends", requireAuth, async (req, res) => {
  try {
    const p = await mojeProsnje(req.user.userId);
    return res.json({ friends: await mojiPrijatelji(req.user.userId), requests_in: p.incoming, requests_out: p.outgoing });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /me/friends/plans -> { events: [ {dogodek..., club_name, club_logo_url, friends: [{id, username, avatar_url}]} ] }
// Prihajajoči objavljeni dogodki, na katere ima vsaj en prijatelj VELJAVNO vstopnico —
// samo prijatelji, ki imajo vklopljeno share_plans_with_friends (zasebnost, invarianta I11).
app.get("/me/friends/plans", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `WITH pr AS (
         SELECT CASE WHEN user_a = $1 THEN user_b ELSE user_a END AS id FROM friendships WHERE user_a = $1 OR user_b = $1
       ), gredo AS (
         -- Kdo od prijateljev drži veljavno vstopnico za kateri dogodek (imetnik = prejemnik prenosa, sicer kupec, 008).
         SELECT t.event_id, ${IMETNIK} AS uid
           FROM tickets t JOIN orders o ON o.id = t.order_id
          WHERE t.status = 'valid' AND o.status IN ('paid','partially_refunded')
            AND ${IMETNIK} IN (SELECT id FROM pr)
          GROUP BY 1, 2
       ), po_dogodku AS (
         SELECT g.event_id,
                jsonb_agg(jsonb_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) ORDER BY LOWER(u.username)) AS friends
           FROM gredo g JOIN users u ON u.id = g.uid
          WHERE u.share_plans_with_friends
          GROUP BY g.event_id
       )
       SELECT e.*, cl.name AS club_name, cl.logo_url AS club_logo_url, p.friends
         FROM (SELECT ${STOLPCI_DOGODKA} FROM events) e
         JOIN po_dogodku p ON p.event_id = e.id
         JOIN clubs cl ON cl.id = e.club_id
        WHERE e.start_at > NOW() AND e.status = 'published' AND NOT cl.hidden
        ORDER BY e.start_at ASC
        LIMIT 50`,
      [req.user.userId]
    );
    return res.json({ events: r.rows });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /me/friends/requests — telo: { user_id } ali { username }.
// 201 { request } ko prošnja čaka; 200 { friend } če je nasprotna prošnja že čakala (takoj prijatelja).
// 409 already_friends | already_requested; 404 no_account; 400 self.
app.post("/me/friends/requests", requireAuth, omeji({ kljuc: "prosnja", najvec: 30, oknoSekund: 3600 }), async (req, res) => {
  const b = req.body || {};
  let cilj = null;
  try {
    if (b.user_id !== undefined) {
      const id = celoId(b.user_id);
      if (!id) return res.status(400).send("Invalid user_id.");
      const r = await pool.query(`SELECT ${POLJA_PRIJATELJA}, u.email_verified FROM users u WHERE u.id = $1`, [id]);
      cilj = r.rows[0] || null;
    } else if (typeof b.username === "string") {
      const ime = b.username.trim();
      if (!/^[a-zA-Z0-9_]{3,20}$/.test(ime)) return res.status(400).send("Invalid username.");
      const r = await pool.query(`SELECT ${POLJA_PRIJATELJA}, u.email_verified FROM users u WHERE LOWER(u.username) = LOWER($1)`, [ime]);
      cilj = r.rows[0] || null;
    } else return res.status(400).send("user_id or username is required.");
    if (!cilj || !cilj.email_verified) return res.status(404).json({ error: "no_account", message: "No Outly account with this username." });
    if (Number(cilj.id) === Number(req.user.userId)) return res.status(400).send("You can't add yourself.");
    if (await staPrijatelja(req.user.userId, cilj.id)) return res.status(409).json({ error: "already_friends", message: "You are already friends." });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // Nasprotna prošnja že čaka -> sprejmi jo (oba sta hotela isto).
      const obratna = await client.query(
        "SELECT id FROM friend_requests WHERE from_user_id = $1 AND to_user_id = $2 AND status = 'pending' FOR UPDATE", [cilj.id, req.user.userId]
      );
      if (obratna.rows.length) {
        await client.query("UPDATE friend_requests SET status='accepted', responded_at=NOW() WHERE id=$1", [obratna.rows[0].id]);
        await client.query(
          "INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int)) ON CONFLICT DO NOTHING",
          [req.user.userId, cilj.id]
        );
        await client.query("COMMIT");
        return res.status(200).json({ friend: { id: cilj.id, username: cilj.username, avatar_url: cilj.avatar_url }, request: null });
      }
      const ins = await client.query(
        `INSERT INTO friend_requests (from_user_id, to_user_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING RETURNING id, created_at`, [req.user.userId, cilj.id]
      );
      await client.query("COMMIT");
      if (ins.rows.length === 0) return res.status(409).json({ error: "already_requested", message: "A request is already pending." });
      return res.status(201).json({ request: { id: ins.rows[0].id, created_at: ins.rows[0].created_at, user: { id: cilj.id, username: cilj.username, avatar_url: cilj.avatar_url } }, friend: null });
    } catch (e) {
      try { await client.query("ROLLBACK"); } catch (_) {}
      throw e;
    } finally { client.release(); }
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /me/friends/requests/:id/accept -> { friend }. Samo naslovnik čakajoče prošnje.
app.post("/me/friends/requests/:id/accept", requireAuth, async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid request id.");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query(
      `SELECT r.id, r.from_user_id, ${POLJA_PRIJATELJA} FROM friend_requests r JOIN users u ON u.id = r.from_user_id
        WHERE r.id = $1 AND r.to_user_id = $2 AND r.status = 'pending' FOR UPDATE OF r`, [id, req.user.userId]
    );
    if (r.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).send("Request not found or no longer pending."); }
    const p = r.rows[0];
    await client.query(
      "INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int)) ON CONFLICT DO NOTHING",
      [req.user.userId, p.from_user_id]
    );
    await client.query("UPDATE friend_requests SET status='accepted', responded_at=NOW() WHERE id=$1", [id]);
    await client.query("COMMIT");
    return res.json({ friend: { id: p.id, username: p.username, avatar_url: p.avatar_url } });
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch (_) {}
    console.error(e); return res.status(500).send("Server error.");
  } finally { client.release(); }
});

// POST /me/friends/requests/:id/decline -> { ok: true }. Samo naslovnik.
app.post("/me/friends/requests/:id/decline", requireAuth, async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid request id.");
    const r = await pool.query(
      "UPDATE friend_requests SET status='declined', responded_at=NOW() WHERE id=$1 AND to_user_id=$2 AND status='pending' RETURNING id", [id, req.user.userId]
    );
    if (r.rows.length === 0) return res.status(404).send("Request not found or no longer pending.");
    return res.json({ ok: true });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /me/friends/requests/:id -> { ok: true }. Pošiljatelj prekliče svojo čakajočo prošnjo.
app.delete("/me/friends/requests/:id", requireAuth, async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid request id.");
    const r = await pool.query(
      "UPDATE friend_requests SET status='cancelled', responded_at=NOW() WHERE id=$1 AND from_user_id=$2 AND status='pending' RETURNING id", [id, req.user.userId]
    );
    if (r.rows.length === 0) return res.status(404).send("Request not found or no longer pending.");
    return res.json({ ok: true });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /me/friends/:userId -> { ok: true }. Odstrani prijatelja (obojestransko, ker je ena vrstica).
app.delete("/me/friends/:userId", requireAuth, async (req, res) => {
  try {
    const uid = celoId(req.params.userId);
    if (!uid) return res.status(400).send("Invalid user id.");
    const r = await pool.query(
      "DELETE FROM friendships WHERE user_a = LEAST($1::int,$2::int) AND user_b = GREATEST($1::int,$2::int) RETURNING user_a", [req.user.userId, uid]
    );
    if (r.rows.length === 0) return res.status(404).send("Not friends.");
    return res.json({ ok: true });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /business/team/me — član sam zapusti ekipo (tudi vratar).
app.delete("/business/team/me", requireAuth, async (req, res) => {
  try {
    const r = await pool.query("DELETE FROM club_members WHERE user_id=$1 RETURNING club_id", [req.user.userId]);
    if (r.rows.length === 0) return res.status(404).send("You are not in a club team.");
    return res.status(204).send();
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /business/team/:userId — odstrani člana. Manager sme samo vratarje.
app.delete("/business/team/:userId", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const uid = celoId(req.params.userId);
    if (!uid) return res.status(400).send("Invalid user id.");
    const m = await pool.query("SELECT role FROM club_members WHERE club_id=$1 AND user_id=$2", [klub, uid]);
    if (m.rows.length === 0) return res.status(404).send("Member not found.");
    if (req.klub.role === "manager" && m.rows[0].role !== "doorman" && Number(uid) !== Number(req.user.userId)) {
      return res.status(403).send("Only the club owner can remove managers.");
    }
    await pool.query("DELETE FROM club_members WHERE club_id=$1 AND user_id=$2", [klub, uid]);
    return res.json(await odgovorEkipe(req, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on port", port));
