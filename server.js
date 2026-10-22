require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error("SESSION_SECRET must be a unique secret of at least 32 characters in production.");
}
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.includes("REPLACE_WITH")) {
  console.warn("WARNING: Set a unique SESSION_SECRET in .env before using this site beyond local testing.");
}

const db = new Database(path.join(dataDir, "studyhub.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('admin','student')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT 'General',
  due_date TEXT,
  priority TEXT NOT NULL DEFAULT 'Normal',
  completed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT 'General',
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS goals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  target INTEGER NOT NULL DEFAULT 10,
  progress INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const countUsers = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
if (countUsers === 0 && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD &&
    !process.env.ADMIN_PASSWORD.includes("REPLACE_WITH")) {
  const username = String(process.env.ADMIN_USERNAME).trim();
  const password = String(process.env.ADMIN_PASSWORD);
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) throw new Error("ADMIN_USERNAME must be 3–32 letters, numbers, dots, underscores, or hyphens.");
  if (password.length < 14) throw new Error("ADMIN_PASSWORD must be at least 14 characters.");
  db.prepare("INSERT INTO users (username,password_hash,role) VALUES (?,?,?)")
    .run(username, bcrypt.hashSync(password, 12), "admin");
  console.log(`Initial admin account created for username: ${username}`);
} else if (countUsers === 0) {
  console.warn("No accounts exist yet. Set ADMIN_USERNAME and ADMIN_PASSWORD in .env, then restart.");
}

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  }
}));
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(session({
  name: "studyhub.sid",
  secret: sessionSecret || crypto.randomBytes(48).toString("hex"),
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: "sessions.db", dir: dataDir, table: "sessions" }),
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 4
  }
}));
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false,
  message: { error: "Too many login attempts. Try again in 15 minutes." }
});
const writeLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 60, standardHeaders: "draft-7", legacyHeaders: false
});
const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: "Please sign in first." });
  next();
};
const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== "admin") return res.status(403).json({ error: "Administrator access required." });
  next();
};
const csrf = (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const token = req.get("x-csrf-token");
  if (!req.session.csrfToken || !token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: "Security token missing or invalid. Refresh the page and try again." });
  }
  next();
};
app.use("/api", csrf);

app.get("/api/csrf", (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  res.json({ csrfToken: req.session.csrfToken });
});
app.get("/api/me", (req, res) => res.json({ user: req.session.user || null }));
app.post("/api/login", loginLimiter, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (username.length > 32 || password.length > 200) return res.status(400).json({ error: "Invalid username or password." });
    const user = db.prepare("SELECT id,username,password_hash,role FROM users WHERE username = ? COLLATE NOCASE").get(username);
    const valid = user && await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Incorrect username or password." });
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.user = { id: user.id, username: user.username, role: user.role };
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.save(err2 => {
        if (err2) return next(err2);
        res.json({ user: req.session.user, csrfToken: req.session.csrfToken });
      });
    });
  } catch (e) { next(e); }
});
app.post("/api/logout", requireAuth, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("studyhub.sid", { httpOnly: true, sameSite: "strict", secure: isProduction });
    res.json({ ok: true });
  });
});

// Admin-only account creation. Passwords are never returned or emailed.
app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  res.json(db.prepare("SELECT id,username,role,created_at FROM users ORDER BY id").all());
});
app.post("/api/admin/users", requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const role = req.body.role === "admin" ? "admin" : "student";
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) return res.status(400).json({ error: "Username must be 3–32 letters, numbers, dots, underscores, or hyphens." });
  if (password.length < 14 || password.length > 200) return res.status(400).json({ error: "Use a unique password of at least 14 characters." });
  try {
    const result = db.prepare("INSERT INTO users (username,password_hash,role) VALUES (?,?,?)")
      .run(username, bcrypt.hashSync(password, 12), role);
    res.status(201).json({ id: result.lastInsertRowid, username, role, message: "Account created. Share credentials privately with the intended user; they will not be shown again by the server." });
  } catch (e) {
    if (String(e.code).startsWith("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "That username already exists." });
    throw e;
  }
});
app.delete("/api/admin/users/:id", requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.session.user.id) return res.status(400).json({ error: "You cannot delete your own account while signed in." });
  const target = db.prepare("SELECT id,role FROM users WHERE id=?").get(id);
  if (!target) return res.status(404).json({ error: "Account not found." });
  if (target.role === "admin" && db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").get().n < 2)
    return res.status(400).json({ error: "Keep at least one administrator account." });
  db.prepare("DELETE FROM users WHERE id=?").run(id);
  res.json({ ok: true });
});

function resourceRoutes(name, table, fields, orderBy) {
  const selectFields = `id,${fields.join(",")},created_at`;
  app.get(`/api/${name}`, requireAuth, (req, res) => {
    res.json(db.prepare(`SELECT ${selectFields} FROM ${table} WHERE user_id=? ORDER BY ${orderBy}`).all(req.session.user.id));
  });
  app.post(`/api/${name}`, requireAuth, writeLimiter, (req, res) => {
    const values = fields.map(f => req.body[f]);
    const error = validateResource(name, req.body);
    if (error) return res.status(400).json({ error });
    const cols = ["user_id", ...fields];
    const placeholders = cols.map(() => "?").join(",");
    const result = db.prepare(`INSERT INTO ${table} (${cols.join(",")}) VALUES (${placeholders})`)
      .run(req.session.user.id, ...values);
    res.status(201).json(db.prepare(`SELECT ${selectFields} FROM ${table} WHERE id=? AND user_id=?`).get(result.lastInsertRowid, req.session.user.id));
  });
  app.put(`/api/${name}/:id`, requireAuth, writeLimiter, (req, res) => {
    const error = validateResource(name, req.body);
    if (error) return res.status(400).json({ error });
    const assignments = fields.map(f => `${f}=?`).join(",");
    const result = db.prepare(`UPDATE ${table} SET ${assignments}${name === "notes" ? ",updated_at=CURRENT_TIMESTAMP" : ""} WHERE id=? AND user_id=?`)
      .run(...fields.map(f => req.body[f]), Number(req.params.id), req.session.user.id);
    if (!result.changes) return res.status(404).json({ error: "Item not found." });
    res.json(db.prepare(`SELECT ${selectFields} FROM ${table} WHERE id=? AND user_id=?`).get(Number(req.params.id), req.session.user.id));
  });
  app.delete(`/api/${name}/:id`, requireAuth, writeLimiter, (req, res) => {
    const result = db.prepare(`DELETE FROM ${table} WHERE id=? AND user_id=?`).run(Number(req.params.id), req.session.user.id);
    if (!result.changes) return res.status(404).json({ error: "Item not found." });
    res.json({ ok: true });
  });
}
function validateResource(name, body) {
  const title = String(body.title || "").trim();
  if (!title || title.length > 120) return "Title is required and must be under 120 characters.";
  if (name === "assignments") {
    if (String(body.subject || "General").length > 60) return "Subject must be under 60 characters.";
    if (body.due_date && !/^\d{4}-\d{2}-\d{2}$/.test(body.due_date)) return "Use a valid due date.";
    if (!["Low","Normal","High"].includes(body.priority)) return "Invalid priority.";
    if (![0,1,false,true].includes(body.completed)) return "Invalid completion status.";
  }
  if (name === "notes" && String(body.body || "").length > 10000) return "Note body must be under 10,000 characters.";
  if (name === "goals" && (!Number.isInteger(Number(body.target)) || Number(body.target)<1 || Number(body.target)>10000 ||
      !Number.isInteger(Number(body.progress)) || Number(body.progress)<0 || Number(body.progress)>Number(body.target))) return "Invalid goal progress or target.";
  return null;
}
resourceRoutes("assignments", "assignments", ["title","subject","due_date","priority","completed"], "completed, COALESCE(due_date,'9999-12-31'), id DESC");
resourceRoutes("notes", "notes", ["title","subject","body"], "updated_at DESC, id DESC");
resourceRoutes("goals", "goals", ["title","target","progress"], "id DESC");

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "An unexpected server error occurred." });
});
app.listen(PORT, () => console.log(`StudyHub running on http://localhost:${PORT}`));
