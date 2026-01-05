const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "please-change-me";
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "http://localhost:5173";

const dbPath = process.env.DB_PATH || path.join(__dirname, "data.db");
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    current_streak INTEGER DEFAULT 0,
    longest_streak INTEGER DEFAULT 0,
    last_entry_date TEXT,
    onboarding_done INTEGER DEFAULT 0,
    daily_goal_minutes INTEGER,
    weekly_goal_minutes INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
  )
`).run();

// Best-effort migration for existing DBs missing onboarding_done
try {
  db.prepare("ALTER TABLE users ADD COLUMN onboarding_done INTEGER DEFAULT 0").run();
} catch (err) {
  // ignore if column exists
}
try {
  db.prepare("ALTER TABLE users ADD COLUMN daily_goal_minutes INTEGER").run();
} catch (err) {
  // ignore
}
try {
  db.prepare("ALTER TABLE users ADD COLUMN weekly_goal_minutes INTEGER").run();
} catch (err) {
  // ignore
}
try {
  db.prepare("ALTER TABLE users ADD COLUMN created_at TEXT DEFAULT (datetime('now'))").run();
} catch (err) {
  // ignore
}

db.prepare(`
  CREATE TABLE IF NOT EXISTS daily_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    mobile_minutes INTEGER,
    mood INTEGER,
    wake_feeling INTEGER,
    sleep_hours REAL,
    week_avg_mobile_minutes INTEGER,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, date),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`).run();
try {
  db.prepare("ALTER TABLE daily_entries ADD COLUMN notes TEXT").run();
} catch (err) {
  // ignore
}

// If users already have entries, mark onboarding as done to avoid re-showing
db.prepare(`
  UPDATE users
  SET onboarding_done = 1
  WHERE onboarding_done = 0
    AND EXISTS (
      SELECT 1 FROM daily_entries de WHERE de.user_id = users.id
    )
`).run();

app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "..", "client")));

const motivationMessages = [
  "One day at a time beats all at once.",
  "Log it, learn it, lighten up.",
  "Calm is a practice, not a switch.",
  "Screens down, shoulders down, breathe.",
  "Small wins stack into big change.",
];

const createToken = (userId) =>
  jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: "7d" });

const authRequired = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ message: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 6) {
    return res
      .status(400)
      .json({ message: "Email and 6+ character password required" });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const insert = db.prepare(`
      INSERT INTO users (email, password_hash, current_streak, longest_streak, onboarding_done, created_at)
      VALUES (?, ?, 0, 0, 0, datetime('now'))
    `);
    const result = insert.run(email.toLowerCase(), hash);
    const token = createToken(result.lastInsertRowid);
    res
      .cookie("token", token, {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({ email });
  } catch (err) {
    if (err && err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ message: "Email already registered" });
    }
    console.error("register error", err);
    res.status(500).json({ message: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ message: "Missing credentials" });
  }
  const user = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email.toLowerCase());
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });
  const token = createToken(user.id);
  res
    .cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })
    .json({ email: user.email });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token").json({ message: "logged out" });
});

app.get("/api/me", authRequired, (req, res) => {
  const user = db
    .prepare("SELECT email, onboarding_done, created_at as createdAt FROM users WHERE id = ?")
    .get(req.userId);
  res.json(user);
});

app.get("/api/motivation", (req, res) => {
  const msg =
    motivationMessages[Math.floor(Math.random() * motivationMessages.length)];
  res.json({ message: msg });
});

const dateOnly = (value) => {
  if (value) return value;
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const daysBetween = (d1, d2) => {
  const [y1, m1, dDay1] = d1.split("-").map(Number);
  const [y2, m2, dDay2] = d2.split("-").map(Number);
  const a = Date.UTC(y1, m1 - 1, dDay1);
  const b = Date.UTC(y2, m2 - 1, dDay2);
  return Math.round((b - a) / (1000 * 60 * 60 * 24));
};

const updateStreak = (user, today) => {
  if (!user.last_entry_date) {
    return { current: 1, longest: 1, last: today };
  }
  const diff = daysBetween(user.last_entry_date, today);
  if (diff === 0) {
    return {
      current: user.current_streak,
      longest: user.longest_streak,
      last: today,
    };
  }
  if (diff === 1) {
    const current = user.current_streak + 1;
    return {
      current,
      longest: Math.max(user.longest_streak, current),
      last: today,
    };
  }
  return {
    current: 1,
    longest: Math.max(user.longest_streak, 1),
    last: today,
  };
};

app.post("/api/daily", authRequired, (req, res) => {
  const {
    date,
    mobileMinutes,
    mood,
    wakeFeeling,
    sleepHours,
    weekAvgMobileMinutes,
    notes,
  } = req.body || {};
  const normalizedDate = dateOnly(date);
  const user = db
    .prepare("SELECT current_streak, longest_streak, last_entry_date, onboarding_done FROM users WHERE id = ?")
    .get(req.userId);

  // Enforce one entry per calendar day
  if (user.last_entry_date && daysBetween(user.last_entry_date, normalizedDate) === 0) {
    return res.status(429).json({
      message: "Záznam na dnešný deň už existuje. Skús zajtra po 24 hodinách.",
    });
  }

  const streak = updateStreak(user, normalizedDate);

  const upsert = db.prepare(`
    INSERT INTO daily_entries (user_id, date, mobile_minutes, mood, wake_feeling, sleep_hours, week_avg_mobile_minutes, notes)
    VALUES (@user_id, @date, @mobile_minutes, @mood, @wake_feeling, @sleep_hours, @week_avg_mobile_minutes, @notes)
    ON CONFLICT(user_id, date) DO UPDATE SET
      mobile_minutes=excluded.mobile_minutes,
      mood=excluded.mood,
      wake_feeling=excluded.wake_feeling,
      sleep_hours=excluded.sleep_hours,
      week_avg_mobile_minutes=excluded.week_avg_mobile_minutes,
      notes=excluded.notes
  `);

  const payload = {
    user_id: req.userId,
    date: normalizedDate,
    mobile_minutes: Number(mobileMinutes ?? 0),
    mood: Number(mood ?? 0),
    wake_feeling: Number(wakeFeeling ?? 0),
    sleep_hours: Number(sleepHours ?? 0),
    week_avg_mobile_minutes: Number(weekAvgMobileMinutes ?? 0),
    notes: typeof notes === "string" ? notes.slice(0, 1000) : null,
  };

  const updateUser = db.prepare(`
    UPDATE users
    SET current_streak=?, longest_streak=?, last_entry_date=?, onboarding_done=1
    WHERE id=?
  `);

  try {
    const tx = db.transaction(() => {
      upsert.run(payload);
      updateUser.run(streak.current, streak.longest, streak.last, req.userId);
    });
    tx();
    res.json({ streak, date: normalizedDate });
  } catch (err) {
    console.error("daily save error", err);
    res.status(500).json({ message: "Failed to save daily entry" });
  }
});

app.get("/api/daily", authRequired, (req, res) => {
  const limit = Number(req.query.limit || 30);
  const entries = db
    .prepare(
      "SELECT date, mobile_minutes, mood, wake_feeling, sleep_hours, week_avg_mobile_minutes, notes FROM daily_entries WHERE user_id = ? ORDER BY date DESC LIMIT ?"
    )
    .all(req.userId, limit);
  res.json(entries.reverse());
});

app.get("/api/streak", authRequired, (req, res) => {
  const streak = db
    .prepare(
      "SELECT current_streak as current, longest_streak as longest, last_entry_date as lastEntryDate FROM users WHERE id = ?"
    )
    .get(req.userId);
  if (!streak) return res.json({ current: 0, longest: 0 });

  const today = dateOnly();
  if (streak.lastEntryDate) {
    const diff = daysBetween(streak.lastEntryDate, today);
    // Ak uplynul aspoň jeden deň bez záznamu, streak padá na 0
    if (diff >= 1 && streak.current !== 0) {
      db.prepare("UPDATE users SET current_streak=0 WHERE id=?").run(req.userId);
      return res.json({ ...streak, current: 0 });
    }
  }

  res.json(streak);
});

app.get("/api/export/csv", authRequired, (req, res) => {
  const rows = db
    .prepare(
      "SELECT date, mobile_minutes, mood, wake_feeling, sleep_hours, week_avg_mobile_minutes FROM daily_entries WHERE user_id = ? ORDER BY date ASC"
    )
    .all(req.userId);
  const header = "date,mobile_minutes,mood,wake_feeling,sleep_hours,week_avg_mobile_minutes";
  const csv =
    header +
    "\n" +
    rows
      .map((r) =>
        [
          r.date,
          r.mobile_minutes ?? "",
          r.mood ?? "",
          r.wake_feeling ?? "",
          r.sleep_hours ?? "",
          r.week_avg_mobile_minutes ?? "",
        ].join(",")
      )
      .join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=\"detoxify_export.csv\"");
  res.send(csv);
});

app.post("/api/auth/reset", (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ message: "Email je povinný" });
  res.json({ message: "Ak účet existuje, pošleme inštrukcie na obnovu hesla." });
});

app.post("/api/onboarding/done", authRequired, (req, res) => {
  db.prepare("UPDATE users SET onboarding_done=1 WHERE id=?").run(req.userId);
  res.json({ ok: true });
});

app.get("/api/goals", authRequired, (req, res) => {
  const goals = db
    .prepare("SELECT daily_goal_minutes as daily, weekly_goal_minutes as weekly FROM users WHERE id = ?")
    .get(req.userId);
  res.json(goals || { daily: null, weekly: null });
});

app.post("/api/goals", authRequired, (req, res) => {
  const { dailyGoalMinutes, weeklyGoalMinutes } = req.body || {};
  const dailyVal = dailyGoalMinutes != null ? Number(dailyGoalMinutes) : null;
  const weeklyVal = weeklyGoalMinutes != null ? Number(weeklyGoalMinutes) : null;
  db.prepare("UPDATE users SET daily_goal_minutes=?, weekly_goal_minutes=? WHERE id=?").run(
    Number.isFinite(dailyVal) ? dailyVal : null,
    Number.isFinite(weeklyVal) ? weeklyVal : null,
    req.userId
  );
  res.json({ daily: dailyVal, weekly: weeklyVal });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "client", "index.html"));
});

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});
