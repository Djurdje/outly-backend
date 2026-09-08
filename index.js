const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Resend } = require("resend");
const path = require("path");

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

  // Resend NE vrze izjeme ob napaki (npr. nepotrjena domena posiljatelja ali
  // testni kljuc, ki sme posiljati samo lastniku racuna) — vrne { error }.
  // Brez tega zapisa je bila napaka nevidna: registracija je javila "koda poslana",
  // mail pa ni nikoli odsel.
  const r = await resend.emails.send({ from, to: toEmail, subject, html });
  if (r && r.error) {
    console.error("Resend napaka (verifikacija):", JSON.stringify(r.error), "from:", from);
  } else {
    console.log("Resend: verifikacijska koda poslana", r && r.data ? r.data.id : "");
  }
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

  const r = await resend.emails.send({
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
  if (r && r.error) {
    console.error("Resend napaka (ponastavitev gesla):", JSON.stringify(r.error), "from:", from);
  }
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
app.get("/business/clubs/me", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT ${STOLPCI_KLUBA_LASTNIKA} FROM clubs WHERE owner_user_id=$1 LIMIT 1`,
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
      lng: body.lng,
      // Doslej ju lastnik ni mogel nastaviti (samo admin) — ClubInfoView ju rabi.
      genres: body.genres,
      min_age: body.min_age ?? body.minAge
    };

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
      sets.push(`${k} = $${idx++}`);
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
function neobveznaPrijava(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token || !process.env.JWT_SECRET) return next();
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); } catch (_) { /* neprijavljen */ }
  next();
}

// POST /creator-applications — javno, omejeno. Aplikacija ga kliče iz
// "Request for creator"; prijavljenemu uporabniku se prošnja veže na račun.
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
      // Nova vloga v žetonu šele ob osvežitvi; odvzem admina naj velja takoj, ko poteče dostopni žeton (1 h).
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
    if (prekliciZetone) await prekliciVseZetone(id);
    if (b.emailVerified === true) {
      await pool.query("UPDATE email_verification_codes SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL", [id]);
    }
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
const STOLPCI_VSTOPNICE = `t.id, t.order_id, t.event_id, t.serial, t.status, t.used_at, t.created_at`;

async function vstopniceNarocil(idsNarocil) {
  if (!idsNarocil.length) return {};
  const r = await pool.query(
    `SELECT ${STOLPCI_VSTOPNICE} FROM tickets t WHERE t.order_id = ANY($1::bigint[]) ORDER BY t.id`, [idsNarocil]
  );
  const po = {};
  for (const t of r.rows) (po[t.order_id] ||= []).push({ ...t, qr: qrVstopnice(t) });
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

    const nr = await pool.query(`SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, e.start_at, e.poster_url, cl.name AS club_name
       FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = o.club_id WHERE o.id = $1`, [oid]);
    const vst = await vstopniceNarocil([oid]);
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
app.get("/me/tickets", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT ${STOLPCI_VSTOPNICE}, o.public_ref, o.status AS order_status,
              e.title AS event_title, e.start_at, e.end_at, e.poster_url, e.min_age,
              cl.id AS club_id, cl.name AS club_name, cl.address, cl.city, cl.logo_url
       FROM tickets t JOIN orders o ON o.id = t.order_id
       JOIN events e ON e.id = t.event_id JOIN clubs cl ON cl.id = e.club_id
       WHERE o.user_id = $1 AND o.status IN ('paid','partially_refunded')
       ORDER BY (e.start_at >= NOW()) DESC, e.start_at ASC, t.id ASC LIMIT 200`, [req.user.userId]
    );
    return res.json(r.rows.map(t => ({ ...t, qr: qrVstopnice(t) })));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- poslovni del: prodaja ---
async function mojKlubId(req) {
  const r = await pool.query("SELECT id FROM clubs WHERE owner_user_id=$1 LIMIT 1", [req.user.userId]);
  return r.rows.length ? r.rows[0].id : null;
}

// GET /business/sales — povzetek prodaje lastnega kluba, po dogodkih, zadnja naročila.
app.get("/business/sales", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const [povzetek, poDogodkih, zadnja] = await Promise.all([
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
    ]);
    return res.json({
      mode: testniNacinPlacil() ? "test" : "live",
      fee_percent: PROVIZIJA_ODSTOTEK,
      summary: povzetek.rows[0],
      events: poDogodkih.rows,
      recent_orders: zadnja.rows,
    });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /business/events/:id/tickets — vstopnice dogodka (za vrata: kdo je prišel).
app.get("/business/events/:id/tickets", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const r = await pool.query(
      `SELECT ${STOLPCI_VSTOPNICE}, o.public_ref, o.buyer_email, u.username AS buyer_username
       FROM tickets t JOIN orders o ON o.id = t.order_id JOIN events e ON e.id = t.event_id
       LEFT JOIN users u ON u.id = o.user_id
       WHERE t.event_id = $1 AND e.club_id = $2 ORDER BY t.id LIMIT 1000`, [id, klub]
    );
    return res.json(r.rows.map(t => ({ ...t, qr: qrVstopnice(t) })));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /business/tickets/scan — skener na vratih. Telo: { qr } (ali { serial } za ročni vnos).
// Preveri podpis, lastništvo, stanje; vstopnico označi kot uporabljeno. Ponovni sken -> 409.
app.post("/business/tickets/scan", requireAuth, requireRole("business", "admin"), async (req, res) => {
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
      `SELECT ${STOLPCI_VSTOPNICE}, e.club_id, e.title AS event_title, e.start_at, o.status AS order_status, o.public_ref, o.buyer_email
       FROM tickets t JOIN events e ON e.id = t.event_id JOIN orders o ON o.id = t.order_id WHERE t.serial = $1`, [serial]
    );
    if (r.rows.length === 0) return res.status(404).json({ result: "unknown", message: "Ticket not found." });
    const t = r.rows[0];
    if (t.club_id !== klub) return res.status(403).json({ result: "wrong_club", message: "This ticket is for another club's event." });
    if (ev !== undefined && ev !== null && Number(ev) !== t.event_id) return res.status(400).json({ result: "invalid", message: "QR code does not match the ticket." });
    if (!["paid", "partially_refunded"].includes(t.order_status)) return res.status(409).json({ result: "unpaid", message: "Order is not paid." });
    if (t.status === "used") return res.status(409).json({ result: "already_used", message: "Ticket was already scanned.", used_at: t.used_at, ticket: t });
    if (t.status !== "valid") return res.status(409).json({ result: t.status, message: `Ticket is ${t.status}.`, ticket: t });

    const u = await pool.query(
      `UPDATE tickets SET status='used', used_at=NOW(), used_by_user_id=$2, scan_device=$3
       WHERE id=$1 AND status='valid' RETURNING id, serial, status, used_at`,
      [t.id, req.user.userId, String(req.headers["user-agent"] || "").slice(0, 100)]
    );
    if (u.rows.length === 0) return res.status(409).json({ result: "already_used", message: "Ticket was already scanned." });
    return res.status(200).json({ result: "ok", message: "Welcome in.", ticket: { ...t, ...u.rows[0] } });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on port", port));
