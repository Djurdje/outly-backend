const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");

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

// Render nastavi PORT avtomatsko
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on port", port));
