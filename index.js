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
    // payload: { userId, email, username, iat, exp }
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).send("Invalid token.");
  }
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
      "SELECT id, email, username, created_at FROM users WHERE id=$1",
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

    // simple email validation
    if (!cleanEmail.includes("@")) {
      return res.status(400).send("Invalid email.");
    }

    // password validation
    if (password.length < 8) {
      return res.status(400).send("Password too short.");
    }

    // username validation
    if (cleanUsername.length < 3) {
      return res.status(400).send("Username too short.");
    }
    if (cleanUsername.length > 20) {
      return res.status(400).send("Username too long.");
    }
    if (!/^[a-zA-Z0-9_]+$/.test(cleanUsername)) {
      return res.status(400).send("Username invalid. Use letters, numbers, underscore.");
    }

    // Check email uniqueness
    const existingEmail = await pool.query("SELECT id FROM users WHERE email=$1", [cleanEmail]);
    if (existingEmail.rows.length > 0) {
      return res.status(409).send("Email already in use.");
    }

    // Check username uniqueness
    const existingUsername = await pool.query("SELECT id FROM users WHERE username=$1", [cleanUsername]);
    if (existingUsername.rows.length > 0) {
      return res.status(409).send("Username already in use.");
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Insert user
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

    const result = await pool.query(
      "SELECT id, email, username, password_hash FROM users WHERE email=$1",
      [cleanEmail]
    );

    if (result.rows.length === 0) return res.status(401).send("Invalid credentials.");

    const user = result.rows[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send("Invalid credentials.");

    if (!process.env.JWT_SECRET) {
      return res.status(500).send("JWT_SECRET not set.");
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    return res.status(200).json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on port", port));
