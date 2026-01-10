const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false },
});

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
    // payload: { userId, email, username, role, iat, exp }
    req.user = payload;
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
      "SELECT id, email, username, role, created_at FROM users WHERE id=$1",
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
// REGISTER (email + username + password)
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

    // role default je v DB: 'user' (ker si dodal DEFAULT)
    await pool.query(
      "INSERT INTO users (email, password_hash, username) VALUES ($1, $2, $3)",
      [cleanEmail, passwordHash, cleanUsername]
    );

    return res.status(201).send("User created.");
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// LOGIN
// ---------------------------
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).send("Missing email or password.");
    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).send("Invalid input types.");
    }

    const cleanEmail = email.trim().toLowerCase();

    // ✅ dodamo role v SELECT
    const result = await pool.query(
      "SELECT id, email, username, role, password_hash FROM users WHERE email=$1",
      [cleanEmail]
    );

    if (result.rows.length === 0) return res.status(401).send("Invalid credentials.");

    const user = result.rows[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send("Invalid credentials.");

    if (!process.env.JWT_SECRET) return res.status(500).send("JWT_SECRET not set.");

    // ✅ role v token
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
// CLUBS
// ---------------------------

// Public: list clubs
app.get("/clubs", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM clubs ORDER BY created_at DESC LIMIT 100");
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// Public: get single club
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

// Business/Admin: create club profile
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
// EVENTS
// ---------------------------

// Public: list events (upcoming by default)
app.get("/events", async (req, res) => {
  try {
    const { clubId, upcoming = "true" } = req.query;

    let sql = "SELECT * FROM events";
    const params = [];
    const where = [];

    if (clubId) {
      params.push(clubId);
      where.push(`club_id = $${params.length}`);
    }

    if (upcoming === "true") {
      where.push(`start_at >= NOW()`);
    }

    if (where.length > 0) sql += " WHERE " + where.join(" AND ");
    sql += " ORDER BY start_at ASC LIMIT 200";

    const r = await pool.query(sql, params);
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// Public: get single event
app.get("/events/:id", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM events WHERE id=$1", [req.params.id]);
    if (r.rows.length === 0) return res.status(404).send("Event not found.");
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// Business/Admin: create event (only for own club if business)
app.post("/events", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const { clubId, title, description, posterUrl, startAt, endAt, minAge, genres, status } = req.body;

    if (!clubId || !title || !startAt) return res.status(400).send("Missing clubId, title or startAt.");

    // najprej dobimo club, da preverimo ownerja
    const clubR = await pool.query("SELECT id, owner_user_id, min_age, genres FROM clubs WHERE id=$1", [clubId]);
    if (clubR.rows.length === 0) return res.status(404).send("Club not found.");

    const club = clubR.rows[0];

    // business user lahko objavlja samo za svoj klub
    if (req.user.role === "business" && Number(club.owner_user_id) !== Number(req.user.userId)) {
      return res.status(403).send("You can only create events for your own club.");
    }

    const r = await pool.query(
      `INSERT INTO events
      (club_id, title, description, poster_url, start_at, end_at, min_age, genres, status)
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING *`,
      [
        clubId,
        title,
        description || "",
        posterUrl || "",
        startAt,                 // pošlji ISO string iz appa
        endAt || null,
        minAge ?? club.min_age ?? 18,
        Array.isArray(genres) ? genres : (club.genres || []),
        status || "published"
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
