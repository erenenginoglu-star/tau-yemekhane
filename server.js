// server.js - TAÜ Yemekhane
// Better-SQLite3 tabanlı DEMO + Paketler + Premium + QR + EUR kuru + Fotoğraf

const express = require("express");
const bcrypt = require("bcryptjs");
const cookieSession = require("cookie-session");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const multer = require("multer");
const Database = require("better-sqlite3");

// -------- Veritabanı başlat --------
const dbPath = path.join(__dirname, "data.sqlite3");
const db = new Database(dbPath);
db.pragma("foreign_keys = ON");

// -------- Tablolar --------
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    student_no TEXT,
    password_hash TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    is_premium INTEGER NOT NULL DEFAULT 0,
    premium_started_at TEXT,
    photo_url TEXT
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS exchange_rates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    base TEXT NOT NULL,
    target TEXT NOT NULL,
    rate REAL NOT NULL,
    fetched_at TEXT NOT NULL
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS qr_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`).run();

// -------- Express Ayarları --------
const app = express();
app.use(express.json());
app.use(
  cookieSession({
    name: "session",
    secret: "tau-yemekhane-secret",
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
  })
);
app.use(express.static(path.join(__dirname, "public")));

// -------- Fotoğraf Yükleme --------
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `user_${req.session.userId}_${Date.now()}${ext}`);
  },
});
const upload = multer({ storage });

// -------- Yardımcı Fonksiyonlar --------
function dbRun(sql, params = []) {
  const stmt = db.prepare(sql);
  return stmt.run(params);
}
function dbGet(sql, params = []) {
  return db.prepare(sql).get(params);
}
function dbAll(sql, params = []) {
  return db.prepare(sql).all(params);
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Oturum bulunamadı." });
  next();
}

// -------- EUR Kuru API --------
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

async function updateEuroRateFromAPI() {
  try {
    const res = await fetch("https://api.exchangerate.host/latest?base=EUR&symbols=TRY");
    const data = await res.json();
    const rate = data?.rates?.TRY;
    if (rate) {
      dbRun(
        "INSERT INTO exchange_rates (base, target, rate, fetched_at) VALUES (?, ?, ?, ?)",
        ["EUR", "TRY", rate, new Date().toISOString()]
      );
      console.log("💶 EUR/TRY güncellendi:", rate);
    }
  } catch (err) {
    console.error("EUR kuru alınamadı:", err.message);
  }
}
updateEuroRateFromAPI();
setInterval(updateEuroRateFromAPI, 2 * 60 * 60 * 1000);

// -------- API: Kayıt Ol --------
app.post("/api/register", (req, res) => {
  const { name, email, studentNo, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "Lütfen tüm alanları doldurun." });

  const emailLower = email.toLowerCase();
  const existing = dbGet("SELECT id FROM users WHERE email = ?", [emailLower]);
  if (existing) return res.status(409).json({ error: "Bu e-posta kayıtlı." });

  const password_hash = bcrypt.hashSync(password, 10);
  dbRun(
    `INSERT INTO users (name, email, student_no, password_hash, balance, created_at)
     VALUES (?, ?, ?, ?, 0, ?)`,
    [name, emailLower, studentNo || null, password_hash, new Date().toISOString()]
  );
  const userId = db.prepare("SELECT last_insert_rowid() AS id").get().id;
  req.session.userId = userId;
  res.json({ ok: true });
});

// -------- API: Giriş Yap --------
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const user = dbGet("SELECT * FROM users WHERE email = ?", [email.toLowerCase()]);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: "E-posta veya şifre hatalı." });
  req.session.userId = user.id;
  res.json({ ok: true });
});

// -------- API: Çıkış --------
app.post("/api/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// -------- API: Fotoğraf Yükleme --------
app.post("/api/upload-photo", requireAuth, upload.single("photo"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Dosya yüklenmedi." });
  const photoUrl = `/uploads/${req.file.filename}`;
  dbRun("UPDATE users SET photo_url = ? WHERE id = ?", [photoUrl, req.session.userId]);
  res.json({ ok: true, url: photoUrl });
});

// -------- API: QR Token --------
app.post("/api/qr-token", requireAuth, (req, res) => {
  const token = crypto.randomBytes(8).toString("hex");
  const now = new Date();
  const expires = new Date(now.getTime() + 5 * 60 * 1000);
  dbRun(
    "INSERT INTO qr_codes (user_id, token, created_at, expires_at, used) VALUES (?, ?, ?, ?, 0)",
    [req.session.userId, token, now.toISOString(), expires.toISOString()]
  );
  res.json({ ok: true, token, expires_at: expires.toISOString() });
});

// -------- API: Kullanıcı Bilgisi --------
app.get("/api/me", requireAuth, (req, res) => {
  const user = dbGet("SELECT * FROM users WHERE id = ?", [req.session.userId]);
  const txs = dbAll(
    "SELECT * FROM transactions WHERE user_id = ? ORDER BY datetime(created_at) DESC LIMIT 20",
    [req.session.userId]
  );
  const latestRate = dbGet(
    "SELECT rate FROM exchange_rates ORDER BY datetime(fetched_at) DESC LIMIT 1"
  );
  res.json({
    user,
    transactions: txs,
    eurRate: latestRate ? latestRate.rate : null,
  });
});

// -------- Sunucu Başlat --------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 TAÜ Yemekhane sunucusu http://localhost:${PORT} üzerinde aktif!`);
});
