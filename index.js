const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

const app = express();

// dovolimo klice iz appa
app.use(cors());

// da lahko beremo JSON body
app.use(express.json());

// povezava do baze iz Render ENV
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false },
});

// test endpoint
app.get("/", (req, res) => {
  res.send("Outly backend OK");
});

// register endpoint
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1) osnovne validacije
    if (!email || !password) return res.status(400).send("Missing email or password.");
    if (password.length < 8) return res.status(400).send("Password too short.");

    // 2) preveri, če email že obstaja
    const existing = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (existing.rows.length > 0) return res.status(409).send("Email already in use.");

    // 3) hash gesla
    const passwordHash = await bcrypt.hash(password, 12);

    // 4) shrani v bazo
    await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
      [email, passwordHash]
    );

    // 5) uspeh
    return res.status(201).send("User created.");
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// Render nastavi PORT avtomatsko
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on port", port));
