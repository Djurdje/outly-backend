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

// test endpoint
app.get("/", (req, res) => {
  res.send("Outly backend OK");
});

// REGISTER
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).send("Missing email or password.");
    if (password.length < 8) return res.status(400).send("Password too short.");

    const existing = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (existing.rows.length > 0) return res.status(409).send("Email already in use.");

    const passwordHash = await bcrypt.hash(password, 12);

    await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
      [email, passwordHash]
    );

    return res.status(201).send("User created.");
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// LOGIN
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).send("Missing email or password.");

    const result = await pool.query(
      "SELECT id, email, password_hash FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0) return res.status(401).send("Invalid credentials.");

    const user = result.rows[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send("Invalid credentials.");

    if (!process.env.JWT_SECRET) {
      return res.status(500).send("JWT_SECRET not set.");
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
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
