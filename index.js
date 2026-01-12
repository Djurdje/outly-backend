const express = require("express");
const cors = require("cors");
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
// Resend (email) - puščam, ker ga že imaš
// ---------------------------
const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

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
  if (!token) return res.status(401).send("Missing token.");

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).send("Invalid token.");
  }
}

function requireRole(...allowed) {
  return (req, res, next) => {
    if (!allowed.includes(req.user.role)) {
      return res.status(403).send("Forbidden.");
    }
    next();
  };
}

// ---------------------------
// Health
// ---------------------------
app.get("/", (_, res) => res.send("Outly backend OK"));

// ---------------------------
// ME
// ---------------------------
app.get("/me", requireAuth, async (req, res) => {
  const r = await pool.query(
    "SELECT id, email, username, role, avatar_url, email_verified FROM users WHERE id=$1",
    [req.user.userId]
  );
  res.json(r.rows[0]);
});

// ---------------------------
// EVENTS (public)
// - status = DB publish status (npr. 'published')
// - time_status = computed ('coming_soon' | 'popular')
// - upcoming=true => start_at > now()
// - upcoming=false => start_at <= now()
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

    if (upcoming === "true") {
      where.push(`start_at > NOW()`);
    }
    if (upcoming === "false") {
      where.push(`start_at <= NOW()`);
    }

    const order =
      upcoming === "false" ? "ORDER BY start_at DESC" : "ORDER BY start_at ASC";

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
      ${order}
      LIMIT 200
    `;

    const r = await pool.query(sql, params);
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// ---------------------------
// CLUBS (public)
// ---------------------------
app.get("/clubs", async (_, res) => {
  const r = await pool.query("SELECT * FROM clubs ORDER BY created_at DESC");
  res.json(r.rows);
});

app.get("/clubs/:id", async (req, res) => {
  const r = await pool.query("SELECT * FROM clubs WHERE id=$1", [req.params.id]);
  res.json(r.rows[0]);
});

// ---------------------------
// CLUBS (business-only) CREATE
// POST /clubs
// ---------------------------
app.post("/clubs", requireAuth, requireRole("business"), async (req, res) => {
  try {
    const userId = req.user.userId;

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

    if (!name || String(name).trim().length < 2) {
      return res.status(400).send("Missing club name.");
    }

    const sql = `
      INSERT INTO clubs (
        owner_user_id,
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
        genres
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
      )
      RETURNING *
    `;

    const params = [
      userId,
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
    res.status(201).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// ---------------------------
// EVENTS (business-only) CREATE
// POST /events
// Ownership check: club mora biti od tega userja
// ---------------------------
app.post("/events", requireAuth, requireRole("business"), async (req, res) => {
  try {
    const userId = req.user.userId;

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
    ticket_url = ""
  } = req.body || {};


    if (!club_id) return res.status(400).send("Missing club_id.");
    if (!title || String(title).trim().length < 2) {
      return res.status(400).send("Missing title.");
    }
    if (!start_at) return res.status(400).send("Missing start_at.");

    // ownership check
    const owns = await pool.query(
      "SELECT 1 FROM clubs WHERE id=$1 AND owner_user_id=$2",
      [club_id, userId]
    );
    if (owns.rowCount === 0) {
      return res.status(403).send("You don't own this club.");
    }

    const sql = `
      INSERT INTO events (
        club_id,
        title,
        description,
        poster_url,
        start_at,
        end_at,
        min_age,
        genres,
        status,
        ticket_price_cents,
        currency,
        ticket_url
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
    res.status(201).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// ---------------------------
// START
// ---------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Outly backend running on port", port));
