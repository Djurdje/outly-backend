const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Resend } = require("resend");

const app = express();
// Render stoji za proxyjem. Brez tega je req.ip naslov proxyja in bi
// omejevanje veljalo za vse uporabnike skupaj.
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false },
});

// Resend init
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// ---------------------------
// Helpers (verification)
// ---------------------------
function generate6DigitCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

// ---------------------------
// Žetoni (S-06)
// ---------------------------
// Dostopni JWT velja kratko; osveževalni žeton je naključen niz, v bazi samo
// kot odtis, z rotacijo ob vsaki uporabi. Glej migracijo 004.
const DOSTOPNI_VELJA = "1h";
const OSVEZEVALNI_VELJA_DNI = 30;

function podpisiDostopni(user) {
  return jwt.sign(
    { userId: user.id, email: user.email, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: DOSTOPNI_VELJA }
  );
}

async function izdajOsvezevalni(userId, req, zamenjaId = null) {
  const zeton = crypto.randomBytes(48).toString("base64url");
  const naprava = String(req.headers["user-agent"] || "").slice(0, 200);
  const r = await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, device)
     VALUES ($1, $2, NOW() + ($3 || ' days')::interval, $4) RETURNING id`,
    [userId, hashCode(zeton), String(OSVEZEVALNI_VELJA_DNI), naprava]
  );
  if (zamenjaId) {
    await pool.query(
      "UPDATE refresh_tokens SET revoked_at=NOW(), replaced_by=$2 WHERE id=$1",
      [zamenjaId, r.rows[0].id]
    );
  }
  return zeton;
}

async function prekliciVseZetone(userId) {
  await pool.query(
    "UPDATE refresh_tokens SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL",
    [userId]
  );
}

/** Odgovor prijave/osvežitve. `token` ostane zaradi združljivosti s starimi klienti. */
async function odgovorSeje(user, req, zamenjaId = null) {
  return {
    token: podpisiDostopni(user),
    expiresInSeconds: 3600,
    refreshToken: await izdajOsvezevalni(user.id, req, zamenjaId),
  };
}

async function sendVerificationEmail(toEmail, code) {
  if (!resend) {
    console.warn("⚠️ RESEND_API_KEY not set -> skipping email send");
    return;
  }
  const from = process.env.EMAIL_FROM || "onboarding@resend.dev";
  const appName = process.env.APP_NAME || "Outly";

  const subject = `${appName} verification code`;
  const html = `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – Email verification</h2>
      <p>Your verification code is:</p>
      <div style="font-size:28px; font-weight:700; letter-spacing:4px; padding:12px 0">${code}</div>
      <p>This code expires in <b>10 minutes</b>.</p>
      <p>If you didn’t request this, you can ignore this email.</p>
    </div>
  `;

  await resend.emails.send({
    from,
    to: toEmail,
    subject,
    html,
  });
}

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
// Auth middleware (JWT)
// ---------------------------
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) return res.status(401).send("Missing token.");
  if (!process.env.JWT_SECRET) return res.status(500).send("JWT_SECRET not set.");

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { userId, email, username, role, iat, exp }
    next();
  } catch (err) {
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

// test endpoint
app.get("/", (req, res) => {
  res.send("Outly backend OK");
});

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
    return res.status(200).json(result.rows[0]);
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
// REGISTER
// ---------------------------
app.post("/auth/register", omeji({ kljuc: "register", najvec: 5, oknoSekund: 3600 }), async (req, res) => {
  try {
    const { email, password, username } = req.body;

    if (!email || !password || !username) {
      return res.status(400).send("Missing email, password, or username.");
    }
    if (typeof email !== "string" || typeof password !== "string" || typeof username !== "string") {
      return res.status(400).send("Invalid input types.");
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanUsername = username.trim();

    if (!cleanEmail.includes("@")) return res.status(400).send("Invalid email.");
    if (password.length < 8) return res.status(400).send("Password too short.");

    if (cleanUsername.length < 3) return res.status(400).send("Username too short.");
    if (cleanUsername.length > 20) return res.status(400).send("Username too long.");
    if (!/^[a-zA-Z0-9_]+$/.test(cleanUsername)) {
      return res.status(400).send("Username invalid. Use letters, numbers, underscore.");
    }

    const existingEmail = await pool.query("SELECT id FROM users WHERE email=$1", [cleanEmail]);
    if (existingEmail.rows.length > 0) return res.status(409).send("Email already in use.");

    // Brez upoštevanja velikosti črk: "Martin" in "martin" sta isto ime (past 7).
    // Unikatni indeks users_username_lower_key to jamči tudi v bazi; tu dobi
    // uporabnik razumljivo sporočilo namesto napake 500.
    const existingUsername = await pool.query(
      "SELECT id FROM users WHERE LOWER(username)=LOWER($1)", [cleanUsername]
    );
    if (existingUsername.rows.length > 0) return res.status(409).send("Username already in use.");

    const passwordHash = await bcrypt.hash(password, 12);

    // NOTE: role default je tvoj DB default ali NULL; če želiš, lahko tukaj eksplicitno nastaviš 'user'
    const created = await pool.query(
      "INSERT INTO users (email, password_hash, username, email_verified) VALUES ($1,$2,$3,false) RETURNING id, email",
      [cleanEmail, passwordHash, cleanUsername]
    );

    const userId = created.rows[0].id;

    const code = generate6DigitCode();
    const codeHash = hashCode(code);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      `INSERT INTO email_verification_codes (user_id, code_hash, expires_at)
       VALUES ($1,$2,$3)`,
      [userId, codeHash, expiresAt]
    );

    await sendVerificationEmail(cleanEmail, code);

    return res.status(201).json({
      message: "User created. Verification code sent to email.",
      email: cleanEmail
    });
  } catch (err) {
    // Dve registraciji istega imena/e-naslova hkrati: prva zmaga, druga dobi 409.
    if (err && err.code === "23505") {
      const kaj = String(err.constraint || "").includes("email") ? "Email" : "Username";
      return res.status(409).send(`${kaj} already in use.`);
    }
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// VERIFY EMAIL
// ---------------------------
app.post("/auth/verify-email", omeji({ kljuc: "verify", najvec: 10, oknoSekund: 900 }), async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) return res.status(400).send("Missing email or code.");
    if (typeof email !== "string" || typeof code !== "string") return res.status(400).send("Invalid types.");

    const cleanEmail = email.trim().toLowerCase();
    const cleanCode = code.trim();

    if (cleanCode.length !== 6) return res.status(400).send("Code must be 6 digits.");

    const userR = await pool.query("SELECT id, email_verified FROM users WHERE email=$1", [cleanEmail]);
    if (userR.rows.length === 0) return res.status(404).send("User not found.");

    const user = userR.rows[0];
    if (user.email_verified) {
      return res.status(200).json({ message: "Email already verified." });
    }

    const codeR = await pool.query(
      `SELECT id, code_hash, expires_at, used_at, attempts
       FROM email_verification_codes
       WHERE user_id=$1 AND used_at IS NULL
       ORDER BY created_at DESC
       LIMIT 1`,
      [user.id]
    );

    if (codeR.rows.length === 0) return res.status(400).send("No active code. Please resend.");

    const row = codeR.rows[0];
    if (new Date(row.expires_at).getTime() < Date.now()) {
      return res.status(400).send("Code expired. Please resend.");
    }

    // S-03: brez tega je sestmestno kodo (milijon kombinacij) mogoce ugibati
    // neomejeno hitro znotraj desetminutnega okna.
    const NAJVEC_POSKUSOV_KODE = 5;
    if (row.attempts >= NAJVEC_POSKUSOV_KODE) {
      await pool.query("UPDATE email_verification_codes SET used_at=NOW() WHERE id=$1", [row.id]);
      return res.status(400).send("Too many attempts. Please resend the code.");
    }

    const incomingHash = hashCode(cleanCode);
    if (incomingHash !== row.code_hash) {
      const poskusov = row.attempts + 1;
      if (poskusov >= NAJVEC_POSKUSOV_KODE) {
        // Zadnji dovoljeni poskus je bil napacen -> koda se razveljavi.
        await pool.query(
          "UPDATE email_verification_codes SET attempts=$2, used_at=NOW() WHERE id=$1",
          [row.id, poskusov]
        );
      } else {
        await pool.query("UPDATE email_verification_codes SET attempts=$2 WHERE id=$1", [row.id, poskusov]);
      }
      return res.status(400).send("Invalid code.");
    }

    await pool.query("UPDATE users SET email_verified=true WHERE id=$1", [user.id]);
    await pool.query("UPDATE email_verification_codes SET used_at=NOW() WHERE id=$1", [row.id]);

    return res.status(200).json({ message: "Email verified." });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// RESEND CODE
// ---------------------------
app.post("/auth/resend-verification", omeji({ kljuc: "resend", najvec: 5, oknoSekund: 3600 }), async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).send("Missing email.");
    if (typeof email !== "string") return res.status(400).send("Invalid types.");

    const cleanEmail = email.trim().toLowerCase();

    const userR = await pool.query("SELECT id, email_verified FROM users WHERE email=$1", [cleanEmail]);
    if (userR.rows.length === 0) return res.status(404).send("User not found.");

    const user = userR.rows[0];
    if (user.email_verified) return res.status(200).json({ message: "Email already verified." });

    const lastR = await pool.query(
      `SELECT id, expires_at, created_at, used_at
       FROM email_verification_codes
       WHERE user_id=$1 AND used_at IS NULL
       ORDER BY created_at DESC
       LIMIT 1`,
      [user.id]
    );

    if (lastR.rows.length > 0) {
      const last = lastR.rows[0];
      const createdAt = new Date(last.created_at).getTime();
      const tooSoon = (Date.now() - createdAt) < 60 * 1000;
      const notExpired = new Date(last.expires_at).getTime() > Date.now();

      if (tooSoon && notExpired) {
        return res.status(429).send("Please wait a bit before requesting another code.");
      }
    }

    const code = generate6DigitCode();
    const codeHash = hashCode(code);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      `INSERT INTO email_verification_codes (user_id, code_hash, expires_at)
       VALUES ($1,$2,$3)`,
      [user.id, codeHash, expiresAt]
    );

    await sendVerificationEmail(cleanEmail, code);

    return res.status(200).json({ message: "Verification code resent." });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// LOGIN (blocked if not verified)
// ---------------------------
app.post("/auth/login", omeji({ kljuc: "login", najvec: 10, oknoSekund: 900 }), async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).send("Missing email or password.");
    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).send("Invalid input types.");
    }

    const cleanEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `SELECT id, email, username, role, password_hash, email_verified,
              failed_login_count, locked_until
       FROM users WHERE email=$1`,
      [cleanEmail]
    );

    // S-05: enaka napaka za neobstojec racun in napacno geslo. Prej je razlika
    // med "Invalid credentials." in "Wrong password." izdala, kateri e-naslovi
    // so pri nas registrirani.
    const NAPACNO = "Invalid credentials.";

    if (result.rows.length === 0) {
      // Porabimo primerljivo kolicino casa kot pri pravem uporabniku, da se
      // obstoja racuna ne da razbrati iz hitrosti odgovora.
      await bcrypt.compare(password, "$2b$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalid");
      return res.status(401).send(NAPACNO);
    }
    const user = result.rows[0];

    // S-02: zaklep racuna po zaporednih napacnih prijavah. Deluje ne glede na
    // to, od kod poskusi prihajajo - omejevanje po IP naslovu se zaobide z
    // menjavo naslova, tega ne.
    const NAJVEC_POSKUSOV = 8;
    const ZAKLEP_MINUT = 15;

    if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
      const cezKoliko = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 1000);
      res.set("Retry-After", String(cezKoliko));
      return res.status(429).send("Too many failed attempts. Please try again later.");
    }

    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      const poskusov = (user.failed_login_count || 0) + 1;
      if (poskusov >= NAJVEC_POSKUSOV) {
        await pool.query(
          `UPDATE users SET failed_login_count=0, locked_until=NOW() + ($2 || ' minutes')::interval
           WHERE id=$1`,
          [user.id, String(ZAKLEP_MINUT)]
        );
      } else {
        await pool.query("UPDATE users SET failed_login_count=$2 WHERE id=$1", [user.id, poskusov]);
      }
      return res.status(401).send(NAPACNO);
    }

    // Uspesna prijava pobrise stevec.
    if (user.failed_login_count > 0 || user.locked_until) {
      await pool.query("UPDATE users SET failed_login_count=0, locked_until=NULL WHERE id=$1", [user.id]);
    }

    if (!user.email_verified) {
      return res.status(403).send("Email not verified.");
    }

    if (!process.env.JWT_SECRET) return res.status(500).send("JWT_SECRET not set.");

    return res.status(200).json(await odgovorSeje(user, req));
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// OSVEŽITEV IN ODJAVA (S-06)
// ---------------------------
app.post("/auth/refresh", omeji({ kljuc: "refresh", najvec: 60, oknoSekund: 900 }), async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (typeof refreshToken !== "string" || refreshToken.length < 32) {
      return res.status(400).send("Missing refreshToken.");
    }
    if (!process.env.JWT_SECRET) return res.status(500).send("JWT_SECRET not set.");

    const r = await pool.query(
      `SELECT t.id, t.user_id, t.expires_at, t.revoked_at, t.replaced_by,
              u.id AS uid, u.email, u.username, u.role
       FROM refresh_tokens t JOIN users u ON u.id = t.user_id
       WHERE t.token_hash = $1`,
      [hashCode(refreshToken)]
    );
    if (r.rows.length === 0) return res.status(401).send("Invalid refresh token.");
    const t = r.rows[0];

    if (t.revoked_at) {
      if (t.replaced_by) {
        // Žeton je bil že ZAMENJAN z novim in se je pojavil še enkrat: nekdo ima
        // kopijo. Prekličemo vse uporabnikove seje; prijaviti se mora znova.
        await prekliciVseZetone(t.user_id);
        return res.status(401).send("Refresh token reused. All sessions revoked.");
      }
      // Preklican z odjavo / ponastavitvijo gesla: samo zavrnemo, drugih naprav ne diramo.
      return res.status(401).send("Invalid refresh token.");
    }
    if (new Date(t.expires_at).getTime() < Date.now()) {
      await pool.query("UPDATE refresh_tokens SET revoked_at=NOW() WHERE id=$1", [t.id]);
      return res.status(401).send("Refresh token expired.");
    }

    const user = { id: t.uid, email: t.email, username: t.username, role: t.role };
    return res.status(200).json(await odgovorSeje(user, req, t.id));
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Odjava: prekliče osveževalni žeton te naprave. Dostopni JWT poteče sam v 1 uri.
// Ne zahteva veljavnega dostopnega žetona — odjava mora delati tudi, ko je ta potekel.
app.post("/auth/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (typeof refreshToken === "string" && refreshToken.length >= 32) {
      await pool.query(
        "UPDATE refresh_tokens SET revoked_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL",
        [hashCode(refreshToken)]
      );
    }
    // Vedno 200: odjava ne sme "spodleteti" in uporabnika pustiti prijavljenega.
    return res.status(200).json({ message: "Logged out." });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Odjava povsod (vse naprave).
app.post("/auth/logout-all", requireAuth, async (req, res) => {
  try {
    await prekliciVseZetone(req.user.userId);
    return res.status(200).json({ message: "Logged out everywhere." });
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
  phone, phone_verified, date_of_birth, country, genres, onboarded_at, created_at`;

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
// POZABLJENO GESLO
// ---------------------------
// Do zdaj tega ni bilo. Kdor je pozabil geslo, je bil trajno zaklenjen iz
// svojega racuna in ga tudi podpora ni mogla resiti.

async function posljiKodoZaPonastavitev(toEmail, code) {
  if (!resend) {
    console.warn("⚠️ RESEND_API_KEY ni nastavljen -> mail ni poslan");
    return;
  }
  const from = process.env.EMAIL_FROM || "onboarding@resend.dev";
  const appName = process.env.APP_NAME || "Outly";

  await resend.emails.send({
    from,
    to: toEmail,
    subject: `${appName} password reset code`,
    html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – Password reset</h2>
      <p>Your password reset code is:</p>
      <div style="font-size:28px; font-weight:700; letter-spacing:4px; padding:12px 0">${code}</div>
      <p>This code expires in <b>15 minutes</b>.</p>
      <p>If you didn't request this, you can ignore this email — your password stays unchanged.</p>
    </div>`,
  });
}

app.post("/auth/forgot-password", omeji({ kljuc: "forgot", najvec: 5, oknoSekund: 3600 }), async (req, res) => {
  try {
    const { email } = req.body;
    if (typeof email !== "string" || !email.trim()) return res.status(400).send("Missing email.");

    const cleanEmail = email.trim().toLowerCase();

    // VEDNO 200, tudi ce racuna ni. Drugace bi ta pot postala orodje za
    // ugotavljanje, kateri e-naslovi so pri nas registrirani (ista logika kot S-05).
    const ODGOVOR = { message: "If an account exists for that email, a reset code has been sent." };

    const userR = await pool.query("SELECT id FROM users WHERE email=$1", [cleanEmail]);
    if (userR.rows.length === 0) return res.status(200).json(ODGOVOR);

    const userId = userR.rows[0].id;

    // Ne posiljaj nove kode pogosteje kot enkrat na minuto.
    const zadnja = await pool.query(
      `SELECT created_at FROM password_reset_codes
       WHERE user_id=$1 AND used_at IS NULL
       ORDER BY created_at DESC LIMIT 1`,
      [userId]
    );
    if (zadnja.rows.length > 0 &&
        Date.now() - new Date(zadnja.rows[0].created_at).getTime() < 60 * 1000) {
      return res.status(200).json(ODGOVOR);
    }

    const code = generate6DigitCode();
    await pool.query(
      `INSERT INTO password_reset_codes (user_id, code_hash, expires_at)
       VALUES ($1,$2,$3)`,
      [userId, hashCode(code), new Date(Date.now() + 15 * 60 * 1000)]
    );

    await posljiKodoZaPonastavitev(cleanEmail, code);
    return res.status(200).json(ODGOVOR);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.post("/auth/reset-password", omeji({ kljuc: "reset", najvec: 10, oknoSekund: 900 }), async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (typeof email !== "string" || typeof code !== "string" || typeof newPassword !== "string") {
      return res.status(400).send("Missing email, code or newPassword.");
    }
    if (newPassword.length < 8) return res.status(400).send("Password too short.");

    const cleanEmail = email.trim().toLowerCase();
    const cleanCode = code.trim();
    if (cleanCode.length !== 6) return res.status(400).send("Code must be 6 digits.");

    const userR = await pool.query("SELECT id FROM users WHERE email=$1", [cleanEmail]);
    if (userR.rows.length === 0) return res.status(400).send("Invalid or expired code.");
    const userId = userR.rows[0].id;

    const codeR = await pool.query(
      `SELECT id, code_hash, expires_at, attempts
       FROM password_reset_codes
       WHERE user_id=$1 AND used_at IS NULL
       ORDER BY created_at DESC LIMIT 1`,
      [userId]
    );
    if (codeR.rows.length === 0) return res.status(400).send("Invalid or expired code.");

    const row = codeR.rows[0];
    if (new Date(row.expires_at).getTime() < Date.now()) {
      return res.status(400).send("Invalid or expired code.");
    }

    const NAJVEC = 5;
    if (row.attempts >= NAJVEC) {
      await pool.query("UPDATE password_reset_codes SET used_at=NOW() WHERE id=$1", [row.id]);
      return res.status(400).send("Too many attempts. Please request a new code.");
    }

    if (hashCode(cleanCode) !== row.code_hash) {
      const poskusov = row.attempts + 1;
      await pool.query(
        poskusov >= NAJVEC
          ? "UPDATE password_reset_codes SET attempts=$2, used_at=NOW() WHERE id=$1"
          : "UPDATE password_reset_codes SET attempts=$2 WHERE id=$1",
        [row.id, poskusov]
      );
      return res.status(400).send("Invalid or expired code.");
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    // Ponastavitev gesla hkrati odklene racun in razveljavi vse ostale kode.
    await pool.query(
      `UPDATE users SET password_hash=$2, failed_login_count=0, locked_until=NULL WHERE id=$1`,
      [userId, passwordHash]
    );
    await pool.query(
      "UPDATE password_reset_codes SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL",
      [userId]
    );

    // Ponastavitev gesla odjavi vse naprave: osveževalni žetoni so preklicani,
    // dostopni JWT-ji potečejo sami v največ 1 uri (S-06).
    await prekliciVseZetone(userId);
    return res.status(200).json({ message: "Password updated." });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// SPREMEMBA GESLA (prijavljen uporabnik)
// ---------------------------
app.post("/auth/change-password", requireAuth, omeji({ kljuc: "chpass", najvec: 10, oknoSekund: 900 }), async (req, res) => {
  try {
    const { currentPassword, newPassword, refreshToken } = req.body || {};
    if (typeof currentPassword !== "string" || typeof newPassword !== "string") {
      return res.status(400).send("Missing currentPassword or newPassword.");
    }
    if (newPassword.length < 8) return res.status(400).send("Password too short.");
    if (newPassword === currentPassword) return res.status(400).send("New password must be different.");

    const r = await pool.query("SELECT password_hash FROM users WHERE id=$1", [req.user.userId]);
    if (r.rows.length === 0) return res.status(404).send("User not found.");

    const ok = await bcrypt.compare(currentPassword, r.rows[0].password_hash);
    if (!ok) return res.status(401).send("Invalid credentials.");

    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query("UPDATE users SET password_hash=$2 WHERE id=$1", [req.user.userId, hash]);

    // Odjavi VSE DRUGE naprave; ta naprava (njen osveževalni žeton) ostane prijavljena.
    if (typeof refreshToken === "string" && refreshToken.length >= 32) {
      await pool.query(
        "UPDATE refresh_tokens SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL AND token_hash<>$2",
        [req.user.userId, hashCode(refreshToken)]
      );
    } else {
      await prekliciVseZetone(req.user.userId);
    }
    return res.status(200).json({ message: "Password changed." });
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
app.delete("/me", requireAuth, omeji({ kljuc: "delete", najvec: 5, oknoSekund: 3600 }), async (req, res) => {
  try {
    const { password } = req.body || {};
    if (typeof password !== "string" || !password) {
      return res.status(400).send("Password required to delete account.");
    }

    const r = await pool.query("SELECT password_hash FROM users WHERE id=$1", [req.user.userId]);
    if (r.rows.length === 0) return res.status(404).send("User not found.");

    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).send("Invalid credentials.");

    // Brez tabele orders (pred migracijo 002) je izbris preprost.
    if (!obstajajoNarocila) {
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

      await odjemalec.query("COMMIT");
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
  lat, lng, min_age, genres, created_at`;

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
    const pogoji = ["lat IS NOT NULL", "lng IS NOT NULL"];

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
    const r = await pool.query(`SELECT ${JAVNI_STOLPCI_KLUBA} FROM clubs WHERE id=$1`, [req.params.id]);
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
       RETURNING *`,
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
app.get("/business/clubs/me", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM clubs WHERE owner_user_id=$1 LIMIT 1",
      [req.user.userId]
    );

    if (r.rows.length === 0) return res.status(404).send("Club not found.");
    return res.status(200).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.patch("/business/clubs/me", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    // fetch club first (ownership)
    const clubR = await pool.query(
      "SELECT id, owner_user_id FROM clubs WHERE owner_user_id=$1 LIMIT 1",
      [req.user.userId]
    );

    if (clubR.rows.length === 0) return res.status(404).send("Club not found.");

    const clubId = clubR.rows[0].id;

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
      lng: body.lng
    };

    // build dynamic UPDATE only for provided keys
    const sets = [];
    const values = [];
    let idx = 1;

    for (const [k, v] of Object.entries(incoming)) {
      if (v === undefined) continue;
      sets.push(`${k} = $${idx++}`);
      values.push(v);
    }

    if (sets.length === 0) {
      // nothing to update -> return current club
      const cur = await pool.query("SELECT * FROM clubs WHERE id=$1", [clubId]);
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
    const sql = `UPDATE clubs SET ${sets.join(", ")} WHERE id = $${idx} RETURNING *`;

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
        CASE
          WHEN start_at > NOW() THEN 'coming_soon'
          ELSE 'popular'
        END AS time_status`;

// Vsi dogodki lastnega kluba, tudi osnutki in odpovedani. Samo za lastnika.
app.get("/business/events", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const klub = await pool.query("SELECT id FROM clubs WHERE owner_user_id=$1 LIMIT 1", [req.user.userId]);
    if (klub.rows.length === 0) return res.status(404).send("Club not found.");

    const r = await pool.query(
      `SELECT ${STOLPCI_DOGODKA} FROM events WHERE club_id=$1 ORDER BY start_at DESC LIMIT 500`,
      [klub.rows[0].id]
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

    // coming soon vs popular
    if (upcoming === "true") where.push(`start_at > NOW()`);
    if (upcoming === "false") where.push(`start_at <= NOW()`);

    // Javno so vidni SAMO objavljeni dogodki. Osnutki in odpovedani so bili
    // doslej vidni vsakomur; lastnik jih vidi prek GET /business/events.
    where.push(`status = 'published'`);

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
      `SELECT ${STOLPCI_DOGODKA} FROM events WHERE id=$1 AND status='published'`,
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
app.post("/events", requireAuth, requireRole("business", "admin"), async (req, res) => {
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

    if (req.user.role === "business" && Number(club.owner_user_id) !== Number(req.user.userId)) {
      return res.status(403).send("You can only create events for your own club.");
    }

    const finalMinAge = (minAge ?? club.min_age ?? 18);
    const finalGenres = Array.isArray(genres) ? genres : (club.genres || []);

    const r = await pool.query(
      `INSERT INTO events
      (
        club_id, title, description, poster_url, start_at, end_at,
        min_age, genres, status,
        ticket_price_cents, currency, ticket_url
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
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
        ticketUrl
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
  if (req.user.role === "business" && Number(d.owner_user_id) !== Number(req.user.userId)) {
    res.status(403).send("You can only manage events of your own club.");
    return null;
  }
  return d;
}

app.patch("/events/:id", requireAuth, requireRole("business", "admin"), async (req, res) => {
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
    };

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

app.delete("/events/:id", requireAuth, requireRole("business", "admin"), async (req, res) => {
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
         WHERE name ILIKE $1 OR city ILIKE $1 OR description ILIKE $1
         ORDER BY (name ILIKE $2) DESC, name
         LIMIT $3`,
        [vzorec, `${q}%`, limit]
      ),
      pool.query(
        `SELECT e.id, e.club_id, e.title, e.poster_url, e.start_at,
                e.ticket_price_cents, e.currency, c.name AS club_name
         FROM events e JOIN clubs c ON c.id = e.club_id
         WHERE e.status = 'published'
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

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on port", port));
