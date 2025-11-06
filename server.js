// server.js - TAÜ Yemekhane
// SQLite tabanlı DEMO + paketler + premium + QR + EUR kuru

const express = require("express");
const bcrypt = require("bcryptjs");
const cookieSession = require("cookie-session");
const path = require("path");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const fs = require("fs");

// Upload klasörü oluştur
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Multer yapılandırması
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = `user_${req.session.userId}_${Date.now()}${ext}`;
    cb(null, filename);
  },
});
const upload = multer({ storage });
// Eğer Node 18 altı kullanıyorsan:
// npm install node-fetch
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();

// -------- Orta katmanlar --------
app.use(express.json());
app.use(
  cookieSession({
    name: "session",
    secret: "tau-yemekhane-secret",
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
  })
);

// public klasörünü servis et
app.use(express.static(path.join(__dirname, "public")));

// -------- SQLite Veritabanı --------
const dbPath = path.join(__dirname, "data.sqlite3");
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run("PRAGMA foreign_keys = ON");

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      student_no TEXT,
      password_hash TEXT NOT NULL,
      balance REAL NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      is_premium INTEGER NOT NULL DEFAULT 0,
      premium_started_at TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      type TEXT NOT NULL, -- 'load' veya 'spend'
      description TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS exchange_rates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      base TEXT NOT NULL,
      target TEXT NOT NULL,
      rate REAL NOT NULL,
      fetched_at TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS qr_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
});

// -------- Şifre reset tokenları (RAM'de) --------
const resetTokens = new Map(); // token -> { userId, expiresAt }

// -------- Promisify helper'lar --------
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this); // this.lastID vs.
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// -------- Helper fonksiyonlar --------
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Oturum bulunamadı." });
  }
  next();
}

function isValidEmail(email) {
  return typeof email === "string" && email.includes("@") && email.includes(".");
}

async function findUserById(id) {
  return dbGet("SELECT * FROM users WHERE id = ?", [id]);
}

async function getUserTransactions(userId, limit = 50) {
  return dbAll(
    "SELECT * FROM transactions WHERE user_id = ? ORDER BY datetime(created_at) DESC LIMIT ?",
    [userId, limit]
  );
}

async function getUserPackageInfo(userId) {
  const allTx = await dbAll(
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

// --- EUR kuru DB helper'ları ---
async function getLatestEuroRate() {
  return dbGet(
    "SELECT rate, fetched_at FROM exchange_rates WHERE base = 'EUR' AND target = 'TRY' ORDER BY datetime(fetched_at) DESC LIMIT 1"
  );
}

async function insertEuroRate(rate) {
  const now = new Date().toISOString();
  await dbRun(
    "INSERT INTO exchange_rates (base, target, rate, fetched_at) VALUES (?, ?, ?, ?)",
    ["EUR", "TRY", rate, now]
  );
}

// --- EUR/TRY kurunu dış API'den çek ---
async function updateEuroRateFromAPI() {
  try {
    const res = await fetch(
      "https://api.exchangerate.host/latest?base=EUR&symbols=TRY"
    );
    const data = await res.json();
    const rate = data && data.rates && data.rates.TRY;
    if (!rate) throw new Error("Kur verisi alınamadı");

    await insertEuroRate(rate);
    console.log("💶 EUR/TRY güncellendi:", rate);
  } catch (err) {
    console.error("EUR kuru alınamadı:", err.message);
  }
}

// Sunucu açılır açılmaz bir kere, sonra 2 saatte bir çek
updateEuroRateFromAPI();
setInterval(updateEuroRateFromAPI, 2 * 60 * 60 * 1000);

// -------- API: Kayıt Ol --------
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, studentNo, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: "Lütfen tüm zorunlu alanları doldurun." });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Geçerli bir e-posta adresi girin." });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Şifre en az 6 karakter olmalı." });
    }

    const emailLower = email.toLowerCase();

    const existing = await dbGet("SELECT id FROM users WHERE email = ?", [
      emailLower,
    ]);
    if (existing) {
      return res
        .status(409)
        .json({ error: "Bu e-posta ile zaten bir hesap var." });
    }

    const password_hash = bcrypt.hashSync(password, 10);
    const created_at = new Date().toISOString();

    const result = await dbRun(
      `INSERT INTO users (name, email, student_no, password_hash, balance, created_at, is_premium)
       VALUES (?, ?, ?, ?, 0, ?, 0)`,
      [name, emailLower, studentNo || null, password_hash, created_at]
    );

    req.session.userId = result.lastID;
    res.json({ ok: true });
  } catch (err) {
    console.error("register error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// -------- API: Giriş Yap --------
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "E-posta ve şifre zorunlu." });
    }

    const emailLower = email.toLowerCase();
    const user = await dbGet("SELECT * FROM users WHERE email = ?", [emailLower]);

    if (!user) {
      return res
        .status(401)
        .json({ error: "E-posta veya şifre hatalı." });
    }

    const match = bcrypt.compareSync(password, user.password_hash);
    if (!match) {
      return res
        .status(401)
        .json({ error: "E-posta veya şifre hatalı." });
    }

    req.session.userId = user.id;
    res.json({ ok: true });
  } catch (err) {
    console.error("login error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// -------- API: Çıkış --------
app.post("/api/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// -------- API: Şifremi Unuttum (demo) --------
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "E-posta adresi zorunlu." });
    }

    const emailLower = email.toLowerCase();
    const user = await dbGet("SELECT id FROM users WHERE email = ?", [
      emailLower,
    ]);

    if (!user) {
      return res.json({
        ok: true,
        message:
          "Eğer bu e-posta kayıtlıysa, şifre sıfırlama linki oluşturuldu.",
      });
    }

    const token = crypto.randomBytes(16).toString("hex");
    const expiresAt = Date.now() + 60 * 60 * 1000; // 1 saat

    resetTokens.set(token, { userId: user.id, expiresAt });

    const resetLink = `http://localhost:3000/reset.html?token=${token}`;
    console.log("Şifre sıfırlama linki:", resetLink);

    return res.json({
      ok: true,
      message:
        "Eğer bu e-posta kayıtlıysa, şifre sıfırlama linki oluşturuldu. (Geliştirme modunda link konsola yazıldı.)",
    });
  } catch (err) {
    console.error("forgot-password error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// -------- API: Şifre Sıfırlama --------
app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res
        .status(400)
        .json({ error: "Token ve yeni şifre zorunludur." });
    }

    if (password.length < 6) {
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

    const user = await findUserById(entry.userId);
    if (!user) {
      return res.status(400).json({ error: "Kullanıcı bulunamadı." });
    }

    const password_hash = bcrypt.hashSync(password, 10);
    await dbRun("UPDATE users SET password_hash = ? WHERE id = ?", [
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

// -------- API: /api/me (panel verisi) --------
app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const user = await findUserById(userId);

    if (!user) {
      return res.status(500).json({ error: "Kullanıcı bulunamadı." });
    }

    const txs = await getUserTransactions(userId, 50);
    const packageInfo = await getUserPackageInfo(userId);
    const latestRate = await getLatestEuroRate();

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        student_no: user.student_no,
        balance: user.balance,
        created_at: user.created_at,
        is_premium: !!user.is_premium,
      },
      transactions: txs,
      packageInfo,
      eurRate: latestRate ? latestRate.rate : null,
    });
  } catch (err) {
    console.error("/api/me error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// -------- API: Demo Yükleme --------
app.post("/api/demo-load", requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const amount = Number(req.body.amount || 0);
    const source = req.body.source || "card";

    if (amount <= 0) {
      return res.status(400).json({ error: "Geçerli bir tutar girin." });
    }

    const user = await findUserById(userId);
    if (!user) {
      return res.status(500).json({ error: "Kullanıcı bulunamadı." });
    }

    const newBalance = (user.balance || 0) + amount;
    await dbRun("UPDATE users SET balance = ? WHERE id = ?", [
      newBalance,
      userId,
    ]);

    const desc =
      source === "sepa"
        ? "Demo online yükleme (SEPA)"
        : "Demo online yükleme (Kart)";

    await dbRun(
      "INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, ?)",
      [userId, amount, "load", desc, new Date().toISOString()]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error("demo-load error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// -------- API: Aylık Öğle / Akşam Paketi --------
app.post("/api/buy-package", requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { packageType } = req.body; // "lunch" veya "dinner"

    const PACKAGE_PRICE = 1800;
    const MEAL_PRICE = 60;
    const meals = PACKAGE_PRICE / MEAL_PRICE; // 30

    if (packageType !== "lunch" && packageType !== "dinner") {
      return res.status(400).json({ error: "Geçersiz paket tipi." });
    }

    const user = await findUserById(userId);
    if (!user) {
      return res.status(500).json({ error: "Kullanıcı bulunamadı." });
    }

    if (user.balance < PACKAGE_PRICE) {
      return res
        .status(400)
        .json({ error: "Bakiyen bu paketi almak için yeterli değil." });
    }

    const newBalance = user.balance - PACKAGE_PRICE;
    await dbRun("UPDATE users SET balance = ? WHERE id = ?", [
      newBalance,
      userId,
    ]);

    const desc =
      packageType === "lunch"
        ? "Aylık Öğle Yemeği Paketi (30 x 60 TL)"
        : "Aylık Akşam Yemeği Paketi (30 x 60 TL)";

    await dbRun(
      "INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, ?)",
      [userId, -PACKAGE_PRICE, "spend", desc, new Date().toISOString()]
    );

    res.json({ ok: true, meals });
  } catch (err) {
    console.error("buy-package error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// -------- API: Premium Üyelik --------
app.post("/api/subscribe-premium", requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const PREMIUM_PRICE = 299;

    const user = await findUserById(userId);
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
    await dbRun(
      "UPDATE users SET balance = ?, is_premium = 1, premium_started_at = ? WHERE id = ?",
      [newBalance, new Date().toISOString(), userId]
    );

    await dbRun(
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

// -------- API: EUR kuru (frontend için) --------
app.get("/api/exchange-rate", async (req, res) => {
  try {
    let latest = await getLatestEuroRate();
    if (!latest) {
      await updateEuroRateFromAPI();
      latest = await getLatestEuroRate();
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
// -------- API: Profil fotoğrafı yükleme --------
app.post("/api/upload-photo", requireAuth, upload.single("photo"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Dosya yüklenmedi." });
    }

    const userId = req.session.userId;
    const photoUrl = `/uploads/${req.file.filename}`;

    // Veritabanında kullanıcıya ait fotoğraf yolunu saklamak istersen:
    await dbRun("ALTER TABLE users ADD COLUMN photo_url TEXT").catch(() => {}); // eğer yoksa ekler
    await dbRun("UPDATE users SET photo_url = ? WHERE id = ?", [photoUrl, userId]);

    res.json({ ok: true, url: photoUrl });
  } catch (err) {
    console.error("upload-photo error", err);
    res.status(500).json({ error: "Fotoğraf yüklenemedi." });
  }
});

// -------- API: Random QR token (demo) --------
app.post("/api/qr-token", requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const token = crypto.randomBytes(8).toString("hex"); // 16 karakter
    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60 * 1000); // 5 dk geçerli

    await dbRun(
      "INSERT INTO qr_codes (user_id, token, created_at, expires_at, used) VALUES (?, ?, ?, ?, 0)",
      [userId, token, now.toISOString(), expires.toISOString()]
    );

    // Frontend bu token'ı QR koda dönüştürebilir (sadece demo)
    res.json({ ok: true, token, expires_at: expires.toISOString() });
  } catch (err) {
    console.error("/api/qr-token error", err);
    res.status(500).json({ error: "Beklenmeyen bir hata oluştu." });
  }
});

// -------- Sunucu Başlat --------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(
    `TAÜ Yemekhane DEMO sunucusu http://localhost:${PORT} üzerinde çalışıyor (SQLite + EUR kuru + QR)`
  );
});
