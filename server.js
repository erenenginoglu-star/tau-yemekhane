// server.js - TAÜ Yemekhane
// Better-SQLite3 tabanlı DEMO + paketler + premium + QR + EUR kuru + fotoğraf

const express = require("express");
const bcrypt = require("bcryptjs");
const cookieSession = require("cookie-session");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const multer = require("multer");
const Database = require("better-sqlite3");

// -------- Veritabanı --------
const dbPath = path.join(__dirname, "data.sqlite3");
const db = new Database(dbPath);
db.pragma("foreign_keys = ON");

// Tablolar
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
    type TEXT NOT NULL, -- 'load' veya 'spend'
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

// -------- Express & Session --------
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

// -------- Fotoğraf Upload --------
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

// -------- DB helper'lar --------
function dbRun(sql, params = []) {
  return db.prepare(sql).run(params);
}
function dbGet(sql, params = []) {
  return db.prepare(sql).get(params);
}
function dbAll(sql, params = []) {
  return db.prepare(sql).all(params);
}

// -------- Yardımcı Fonksiyonlar --------
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Oturum bulunamadı." });
  }
  next();
}

function isValidEmail(email) {
  return typeof email === "string" && email.includes("@") && email.includes(".");
}

function getUserById(id) {
  return dbGet("SELECT * FROM users WHERE id = ?", [id]);
}

function getUserTransactions(userId, limit = 50) {
  return dbAll(
    "SELECT * FROM transactions WHERE user_id = ? ORDER BY datetime(created_at) DESC LIMIT ?",
    [userId, limit]
  );
}

function getUserPackageInfo(userId) {
  const allTx = dbAll(
    "SELECT description FROM transactions WHERE user_id = ?",
    [userId]
  );
  let lunchPackages = 0;
  let dinnerPackages = 0;

  for (const t of allTx) {
    if (!t.description) continue;
    if (t.description.startsWith("Aylık Öğle Yemeği Paketi")) {
      lunchPackages++;
    } else if (t.description.startsWith("Aylık Akşam Yemeği Paketi")) {
      dinnerPackages++;
    }
  }

  const mealsPerPackage = 30;
  const lunchMeals = lunchPackages * mealsPerPackage;
  const dinnerMeals = dinnerPackages * mealsPerPackage;
  const totalMeals = lunchMeals + dinnerMeals;

  return {
    lunchPackages,
    dinnerPackages,
    lunchMeals,
    dinnerMeals,
    totalMeals,
  };
}

// -------- EUR Kuru --------
const fetchFn =
  typeof fetch === "function"
    ? fetch
    : (...args) => import("node-fetch").then(({ default: f }) => f(...args));

function getLatestEuroRate() {
  return dbGet(
    "SELECT rate, fetched_at FROM exchange_rates WHERE base = 'EUR' AND target = 'TRY' ORDER BY datetime(fetched_at) DESC LIMIT 1"
  );
}

function insertEuroRate(rate) {
  dbRun(
    "INSERT INTO exchange_rates (base, target, rate, fetched_at) VALUES (?, ?, ?, ?)",
    ["EUR", "TRY", rate, new Date().toISOString()]
  );
}

async function updateEuroRateFromAPI() {
  try {
    const res = await fetchFn(
      "https://api.exchangerate.host/latest?base=EUR&symbols=TRY"
    );
    const data = await res.json();
    const rate = data && data.rates && data.rates.TRY;
    if (!rate) throw new Error("Kur verisi alınamadı");
    insertEuroRate(rate);
    console.log("💶 EUR/TRY güncellendi:", rate);
  } catch (err) {
    console.error("EUR kuru alınamadı:", err.message);
  }
}

updateEuroRateFromAPI();
setInterval(updateEuroRateFromAPI, 2 * 60 * 60 * 1000);

// -------- Şifre reset tokenları (RAM'de) --------
const resetTokens = new Map(); // token -> { userId, expiresAt }

// ================== AUTH ==================

// Kayıt
app.post("/api/register", (req, res) => {
  try {
    const { name, email, studentNo, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: "Lütfen tüm zorunlu alanları doldurun." });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Geçerli bir e-posta girin." });
    }
    if (String(password).length < 6) {
      return res
        .status(400)
        .json({ error: "Şifre en az 6 karakter olmalı." });
    }

    const emailLower = email.toLowerCase();
    const existing = dbGet("SELECT id FROM users WHERE email = ?", [emailLower]);
    if (existing) {
      return res.status(409).json({ error: "Bu e-posta ile hesap var." });
    }

    const password_hash = bcrypt.hashSync(password, 10);
    const created_at = new Date().toISOString();

    const result = dbRun(
      `INSERT INTO users (name, email, student_no, password_hash, balance, created_at, is_premium)
       VALUES (?, ?, ?, ?, 0, ?, 0)`,
      [name, emailLower, studentNo || null, password_hash, created_at]
    );

    req.session.userId = result.lastInsertRowid;
    res.json({ ok: true });
  } catch (err) {
    console.error("register error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// Giriş
app.post("/api/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "E-posta ve şifre zorunlu." });
    }

    const user = dbGet("SELECT * FROM users WHERE email = ?", [
      email.toLowerCase(),
    ]);
    if (!user) {
      return res.status(401).json({ error: "E-posta veya şifre hatalı." });
    }

    const match = bcrypt.compareSync(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "E-posta veya şifre hatalı." });
    }

    req.session.userId = user.id;
    res.json({ ok: true });
  } catch (err) {
    console.error("login error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// Çıkış
app.post("/api/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// Şifremi unuttum
app.post("/api/forgot-password", (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "E-posta zorunlu." });
    }

    const user = dbGet("SELECT id FROM users WHERE email = ?", [
      email.toLowerCase(),
    ]);

    if (!user) {
      return res.json({
        ok: true,
        message:
          "Eğer bu e-posta kayıtlıysa, şifre sıfırlama linki oluşturuldu.",
      });
    }

    const token = crypto.randomBytes(16).toString("hex");
    const expiresAt = Date.now() + 60 * 60 * 1000;
    resetTokens.set(token, { userId: user.id, expiresAt });

    const resetLink = `http://localhost:3000/reset.html?token=${token}`;
    console.log("Şifre sıfırlama linki:", resetLink);

    res.json({
      ok: true,
      message:
        "Eğer bu e-posta kayıtlıysa, şifre sıfırlama linki oluşturuldu. (Geliştirmede link konsola yazıldı.)",
    });
  } catch (err) {
    console.error("forgot-password error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// Şifre sıfırlama
app.post("/api/reset-password", (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) {
      return res
        .status(400)
        .json({ error: "Token ve yeni şifre zorunlu." });
    }
    if (String(password).length < 6) {
      return res
        .status(400)
        .json({ error: "Şifre en az 6 karakter olmalı." });
    }

    const entry = resetTokens.get(token);
    if (!entry || entry.expiresAt < Date.now()) {
      return res.status(400).json({
        error: "Bu şifre sıfırlama linki geçersiz veya süresi dolmuş.",
      });
    }

    const user = getUserById(entry.userId);
    if (!user) {
      return res.status(400).json({ error: "Kullanıcı bulunamadı." });
    }

    const password_hash = bcrypt.hashSync(password, 10);
    dbRun("UPDATE users SET password_hash = ? WHERE id = ?", [
      password_hash,
      user.id,
    ]);
    resetTokens.delete(token);

    res.json({ ok: true });
  } catch (err) {
    console.error("reset-password error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// ================== HESAP / PANEL ==================

// /api/me
app.get("/api/me", requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    const user = getUserById(userId);
    if (!user) {
      return res.status(500).json({ error: "Kullanıcı bulunamadı." });
    }

    const txs = getUserTransactions(userId, 50);
    const packageInfo = getUserPackageInfo(userId);
    const latestRate = getLatestEuroRate();

    res.json({
      user,
      transactions: txs,
      packageInfo,
      eurRate: latestRate ? latestRate.rate : null,
    });
  } catch (err) {
    console.error("/api/me error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// Demo bakiye yükleme
app.post("/api/demo-load", requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    const amount = Number(req.body.amount || 0);
    const source = req.body.source || "card";

    if (!(amount > 0)) {
      return res.status(400).json({ error: "Geçerli bir tutar girin." });
    }

    const user = getUserById(userId);
    if (!user) {
      return res.status(500).json({ error: "Kullanıcı bulunamadı." });
    }

    const newBalance = (user.balance || 0) + amount;
    dbRun("UPDATE users SET balance = ? WHERE id = ?", [newBalance, userId]);

    const desc =
      source === "sepa"
        ? "Demo online yükleme (SEPA)"
        : "Demo online yükleme (Kart)";

    dbRun(
      "INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, ?)",
      [userId, amount, "load", desc, new Date().toISOString()]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error("demo-load error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// Paket satın alma
app.post("/api/buy-package", requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    const { packageType } = req.body;

    const PACKAGE_PRICE = 1800;
    const MEAL_PRICE = 60;
    const meals = PACKAGE_PRICE / MEAL_PRICE; // 30

    if (packageType !== "lunch" && packageType !== "dinner") {
      return res.status(400).json({ error: "Geçersiz paket tipi." });
    }

    const user = getUserById(userId);
    if (!user) {
      return res.status(500).json({ error: "Kullanıcı bulunamadı." });
    }

    if (user.balance < PACKAGE_PRICE) {
      return res
        .status(400)
        .json({ error: "Bakiyen bu paketi almak için yeterli değil." });
    }

    const newBalance = user.balance - PACKAGE_PRICE;
    dbRun("UPDATE users SET balance = ? WHERE id = ?", [newBalance, userId]);

    const desc =
      packageType === "lunch"
        ? "Aylık Öğle Yemeği Paketi (30 x 60 TL)"
        : "Aylık Akşam Yemeği Paketi (30 x 60 TL)";

    dbRun(
      "INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, ?)",
      [userId, -PACKAGE_PRICE, "spend", desc, new Date().toISOString()]
    );

    res.json({ ok: true, meals });
  } catch (err) {
    console.error("buy-package error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// Premium üyelik
app.post("/api/subscribe-premium", requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    const PREMIUM_PRICE = 299;

    const user = getUserById(userId);
    if (!user) {
      return res.status(500).json({ error: "Kullanıcı bulunamadı." });
    }

    if (user.is_premium) {
      return res.status(400).json({ error: "Zaten Premium üyeliğin aktif." });
    }

    if (user.balance < PREMIUM_PRICE) {
      return res
        .status(400)
        .json({ error: "Bakiyen Premium almak için yeterli değil." });
    }

    const newBalance = user.balance - PREMIUM_PRICE;
    dbRun(
      "UPDATE users SET balance = ?, is_premium = 1, premium_started_at = ? WHERE id = ?",
      [newBalance, new Date().toISOString(), userId]
    );

    dbRun(
      "INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, ?)",
      [
        userId,
        -PREMIUM_PRICE,
        "spend",
        "TAÜ Yemekhane Premium Üyelik (1 Ay)",
        new Date().toISOString(),
      ]
    );

    res.json({ ok: true, is_premium: true });
  } catch (err) {
    console.error("subscribe-premium error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// Fotoğraf yükleme
app.post("/api/upload-photo", requireAuth, upload.single("photo"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Dosya yüklenmedi." });
    }
    const userId = req.session.userId;
    const photoUrl = `/uploads/${req.file.filename}`;
    dbRun("UPDATE users SET photo_url = ? WHERE id = ?", [photoUrl, userId]);
    res.json({ ok: true, url: photoUrl });
  } catch (err) {
    console.error("upload-photo error", err);
    res.status(500).json({ error: "Fotoğraf yüklenemedi." });
  }
});

// EUR kuru frontend için
app.get("/api/exchange-rate", async (req, res) => {
  try {
    let latest = getLatestEuroRate();
    if (!latest) {
      await updateEuroRateFromAPI();
      latest = getLatestEuroRate();
    }
    if (!latest) {
      return res.status(500).json({ error: "Kur verisi alınamadı." });
    }
    res.json({
      base: "EUR",
      target: "TRY",
      rate: latest.rate,
      fetched_at: latest.fetched_at,
    });
  } catch (err) {
    console.error("/api/exchange-rate error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// QR token (demo)
app.post("/api/qr-token", requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    const token = crypto.randomBytes(8).toString("hex");
    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60 * 1000);

    dbRun(
      "INSERT INTO qr_codes (user_id, token, created_at, expires_at, used) VALUES (?, ?, ?, ?, 0)",
      [userId, token, now.toISOString(), expires.toISOString()]
    );

    res.json({ ok: true, token, expires_at: expires.toISOString() });
  } catch (err) {
    console.error("/api/qr-token error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// -------- Sunucu --------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(
    `🚀 TAÜ Yemekhane DEMO sunucusu http://localhost:${PORT} üzerinde çalışıyor`
  );
});
