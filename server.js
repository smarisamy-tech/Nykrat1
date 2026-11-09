// Nykra — minimal real authentication backend
// Signup + login with bcrypt-hashed passwords, session-based auth,
// and an admin view that shows ACCOUNT ACTIVITY ONLY — never passwords.

require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-in-.env';
const SALT_ROUNDS = 12;

// ---------- Database ----------
const db = new Database(path.join(__dirname, 'nykra.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT
  );
`);

const insertUser = db.prepare(
  `INSERT INTO users (email, password_hash) VALUES (?, ?)`
);
const findUserByEmail = db.prepare(`SELECT * FROM users WHERE email = ?`);
const findUserById = db.prepare(
  `SELECT id, email, created_at, last_login_at FROM users WHERE id = ?`
);
const touchLastLogin = db.prepare(
  `UPDATE users SET last_login_at = datetime('now') WHERE id = ?`
);
const listUsersForAdmin = db.prepare(
  `SELECT id, email, created_at, last_login_at FROM users ORDER BY created_at DESC`
);

// ---------- App ----------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      // secure: true,  // enable once served over HTTPS
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not signed in.' });
  next();
}

// Very small email sanity check — not a substitute for verification email flow.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---- Sign up ----
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }
  if (!EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const existing = findUserByEmail.get(email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: 'An account with that email already exists.' });
  }

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const info = insertUser.run(email.toLowerCase(), hash);

  req.session.userId = info.lastInsertRowid;
  res.status(201).json({ ok: true, userId: info.lastInsertRowid });
});

// ---- Log in ----
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const user = findUserByEmail.get(email.toLowerCase());
  if (!user) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }

  touchLastLogin.run(user.id);
  req.session.userId = user.id;
  res.json({ ok: true });
});

// ---- Log out ----
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ---- Current user ----
app.get('/api/me', requireAuth, (req, res) => {
  const user = findUserById.get(req.session.userId);
  res.json({ user });
});

// ---- Admin: account activity only, never passwords or hashes ----
// In a real deployment, gate this behind an admin role check, not just a session.
app.get('/api/admin/users', requireAuth, (req, res) => {
  const rows = listUsersForAdmin.all();
  res.json({ users: rows });
});

app.listen(PORT, () => {
  console.log(`Nykra auth backend running on http://localhost:${PORT}`);
});
