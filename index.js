const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Resend } = require("resend");

const app = express();
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
      "SELECT id, email, username, role, avatar_url, email_verified, created_at FROM users WHERE id=$1",
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
// REGISTER
// ---------------------------
app.post("/auth/register", async (req, res) => {
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

    const existingUsername = await pool.query("SELECT id FROM users WHERE username=$1", [cleanUsername]);
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
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// VERIFY EMAIL
// ---------------------------
app.post("/auth/verify-email", async (req, res) => {
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
      `SELECT id, code_hash, expires_at, used_at
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

    const incomingHash = hashCode(cleanCode);
    if (incomingHash !== row.code_hash) {
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
app.post("/auth/resend-verification", async (req, res) => {
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
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).send("Missing email or password.");
    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).send("Invalid input types.");
    }

    const cleanEmail = email.trim().toLowerCase();

    const result = await pool.query(
      "SELECT id, email, username, role, password_hash, email_verified FROM users WHERE email=$1",
      [cleanEmail]
    );

    if (result.rows.length === 0) return res.status(401).send("Invalid credentials.");
    const user = result.rows[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send("Wrong password.");

    if (!user.email_verified) {
      return res.status(403).send("Email not verified.");
    }

    if (!process.env.JWT_SECRET) return res.status(500).send("JWT_SECRET not set.");

    const token = jwt.sign(
      { userId: user.id, email: user.email, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    return res.status(200).json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// CLUBS (public + business create)
// ---------------------------
app.get("/clubs", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM clubs ORDER BY created_at DESC LIMIT 100");
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

app.get("/clubs/:id", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM clubs WHERE id=$1", [req.params.id]);
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

app.get("/cloudinary/signature", requireAuth, async (req, res) => {
  try {
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(500).send("Cloudinary env vars not set.");
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const folder = process.env.CLOUDINARY_FOLDER || "outly";

    const paramsToSign = { timestamp, folder };

    const signature = cloudinarySignature(paramsToSign, apiSecret);

    return res.status(200).json({
      timestamp,
      signature,
      apiKey,
      cloudName,
      folder
    });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});


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

    values.push(clubId);
    const sql = `UPDATE clubs SET ${sets.join(", ")} WHERE id = $${idx} RETURNING *`;

    const updated = await pool.query(sql, values);
    return res.status(200).json(updated.rows[0]);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});


// ---------------------------
// EVENTS (updated: upcoming true/false + time_status + ticket fields)
// ---------------------------
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

    const sql = `
      SELECT
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
        END AS time_status
      FROM events
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
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
    const r = await pool.query(
      `SELECT
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
        END AS time_status
      FROM events
      WHERE id=$1`,
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

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on port", port));
