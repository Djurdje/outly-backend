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
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
});

// ---------------------------
// Resend
// ---------------------------
const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

// ---------------------------
// Helpers (email verification)
// ---------------------------
function generate6DigitCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

async function sendVerificationEmail(toEmail, code) {
  if (!resend) return;

  const from = process.env.EMAIL_FROM || "onboarding@resend.dev";
  const appName = process.env.APP_NAME || "Outly";

  await resend.emails.send({
    from,
    to: toEmail,
    subject: `${appName} verification code`,
    html: `<h2>${appName}</h2><p>Your code:</p><h1>${code}</h1>`,
  });
}

// ---------------------------
// Auth middleware
// ---------------------------
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user || !allowed.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

// ---------------------------
// Health
// ---------------------------
app.get("/", (_, res) => res.send("Outly backend OK"));

// ---------------------------
// AUTH
// ---------------------------

// Register -> create user + send verification code
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, username } = req.body || {};
    if (!email || !password || !username) {
      return res.status(400).json({ error: "email, password, username required" });
    }

    const existing = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (existing.rows.length) {
      return res.status(409).json({ error: "Email already in use" });
    }

    const pwHash = await bcrypt.hash(password, 10);

    // Default role: user (spremeni, če imaš drug standard)
    const created = await pool.query(
      `INSERT INTO users (email, password_hash, username, role, avatar_url, email_verified)
       VALUES ($1,$2,$3,'user','',false)
       RETURNING id, email, username, role, avatar_url, email_verified`,
      [email, pwHash, username]
    );

    const user = created.rows[0];

    const code = generate6DigitCode();
    const codeHash = hashCode(code);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    await pool.query(
      `INSERT INTO email_verification_codes (user_id, code_hash, expires_at)
       VALUES ($1,$2,$3)`,
      [user.id, codeHash, expiresAt]
    );

    await sendVerificationEmail(email, code);

    res.json({ ok: true, userId: user.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Verify email by code
app.post("/auth/verify-email", async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) {
      return res.status(400).json({ error: "email and code required" });
    }

    const u = await pool.query("SELECT id, email_verified FROM users WHERE email=$1", [email]);
    if (!u.rows.length) return res.status(404).json({ error: "User not found" });

    const userId = u.rows[0].id;

    const r = await pool.query(
      `SELECT code_hash, expires_at, used_at
       FROM email_verification_codes
       WHERE user_id=$1
       ORDER BY expires_at DESC
       LIMIT 1`,
      [userId]
    );

    if (!r.rows.length) return res.status(400).json({ error: "No verification code" });

    const row = r.rows[0];
    if (row.used_at) return res.status(400).json({ error: "Code already used" });
    if (new Date(row.expires_at).getTime() < Date.now()) {
      return res.status(400).json({ error: "Code expired" });
    }

    const incomingHash = hashCode(code);
    if (incomingHash !== row.code_hash) {
      return res.status(400).json({ error: "Invalid code" });
    }

    await pool.query("UPDATE users SET email_verified=true WHERE id=$1", [userId]);
    await pool.query(
      "UPDATE email_verification_codes SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL",
      [userId]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Resend verification code
app.post("/auth/resend-verification", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "email required" });

    const u = await pool.query("SELECT id, email_verified FROM users WHERE email=$1", [email]);
    if (!u.rows.length) return res.status(404).json({ error: "User not found" });
    if (u.rows[0].email_verified) return res.json({ ok: true });

    const userId = u.rows[0].id;

    const code = generate6DigitCode();
    const codeHash = hashCode(code);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      `INSERT INTO email_verification_codes (user_id, code_hash, expires_at)
       VALUES ($1,$2,$3)`,
      [userId, codeHash, expiresAt]
    );

    await sendVerificationEmail(email, code);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Login (blocked if email not verified)
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email and password required" });
    }

    const r = await pool.query(
      "SELECT id, email, password_hash, role, email_verified FROM users WHERE email=$1",
      [email]
    );
    if (!r.rows.length) return res.status(401).json({ error: "Invalid credentials" });

    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    if (!user.email_verified) {
      return res.status(403).json({ error: "Email not verified" });
    }

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------------------
// ME
// ---------------------------
app.get("/me", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT id, email, username, role, avatar_url, email_verified FROM users WHERE id=$1",
      [req.user.userId]
    );
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------------------
// EVENTS (public list + filters)
// ---------------------------
app.get("/events", async (req, res) => {
  try {
    const { clubId, upcoming } = req.query;

    const where = [];
    const params = [];

    if (clubId) {
      params.push(clubId);
      where.push(`club_id = $${params.length}`);
    }

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
    res.status(500).json({ error: "Server error" });
  }
});

// Create event (business-only, must own the club)
app.post("/events", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const {
      club_id,
      title,
      description = "",
      poster_url = "",
      start_at,
      end_at = null,
      min_age = 18,
      genres = [],
      status = "published",
      ticket_price_cents = null,
      currency = "EUR",
      ticket_url = "",
    } = req.body || {};

    if (!club_id || !title || !start_at) {
      return res.status(400).json({ error: "club_id, title, start_at required" });
    }

    // ownership check
    const club = await pool.query("SELECT id, owner_user_id FROM clubs WHERE id=$1", [club_id]);
    if (!club.rows.length) return res.status(404).json({ error: "Club not found" });

    if (req.user.role !== "admin" && club.rows[0].owner_user_id !== req.user.userId) {
      return res.status(403).json({ error: "You do not own this club" });
    }

    const sql = `
      INSERT INTO events (
        club_id, title, description, poster_url, start_at, end_at,
        min_age, genres, status, ticket_price_cents, currency, ticket_url
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING *
    `;

    const params = [
      club_id,
      title,
      description,
      poster_url,
      start_at,
      end_at,
      min_age,
      Array.isArray(genres) ? genres : [],
      status,
      ticket_price_cents,
      currency,
      ticket_url,
    ];

    const r = await pool.query(sql, params);
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------------------
// CLUBS
// ---------------------------
app.get("/clubs", async (_, res) => {
  try {
    const r = await pool.query("SELECT * FROM clubs ORDER BY created_at DESC");
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/clubs/:id", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM clubs WHERE id=$1", [req.params.id]);
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Create club (business-only)
app.post("/clubs", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const {
      name,
      logo_url = "",
      banner_url = "",
      description = "",
      contact_email = "",
      contact_phone = "",
      instagram = "",
      website = "",
      address = "",
      city = "",
      country = "",
      lat = null,
      lng = null,
      min_age = 18,
      genres = [],
    } = req.body || {};

    if (!name) return res.status(400).json({ error: "name required" });

    const sql = `
      INSERT INTO clubs (
        owner_user_id, name, logo_url, banner_url, description,
        contact_email, contact_phone, instagram, website,
        address, city, country, lat, lng, min_age, genres
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
      RETURNING *
    `;

    const params = [
      req.user.userId,
      name,
      logo_url,
      banner_url,
      description,
      contact_email,
      contact_phone,
      instagram,
      website,
      address,
      city,
      country,
      lat,
      lng,
      min_age,
      Array.isArray(genres) ? genres : [],
    ];

    const r = await pool.query(sql, params);
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------------------
// START
// ---------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Outly backend running on port", port));
