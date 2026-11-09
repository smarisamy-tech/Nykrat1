# Nykra — Real Authentication Backend

A minimal, genuine login system: real signup, hashed passwords, sessions.

## What this is (and isn't)
- Passwords are hashed with **bcrypt** before storage — the database never contains
  a plaintext password, and neither you nor any admin view can ever read one back.
- Login creates a server-side **session** (cookie-based), the standard way real
  sites keep you signed in.
- The admin endpoint (`/api/admin/users`) shows account **activity** (email, signup
  date, last login) — never passwords or password hashes. That's intentional: a
  legitimate system is never designed to reveal what a user typed as their password,
  even to the site owner.

## Setup
```bash
npm install
cp .env.example .env
# edit .env and set a long random SESSION_SECRET
npm start
```
Then open `http://localhost:3000` — you'll see tabs for **Sign in** / **Create account**.

## Files
- `server.js` — Express API: `/api/signup`, `/api/login`, `/api/logout`, `/api/me`,
  `/api/admin/users`
- `public/index.html` — real sign-in / sign-up form (talks to the API, not a demo)
- `public/account.html` — a signed-in user's own account info
- `nykra.db` — SQLite database file, created automatically on first run

## Before using this in production
- Put it behind HTTPS and set `cookie.secure = true` in `server.js`.
- Gate `/api/admin/users` behind an actual admin **role** check (e.g. an `is_admin`
  column), not just "is logged in" — right now any signed-in user can view it, which
  is fine for local testing but not for a real deployment.
- Add rate limiting on `/api/login` to slow down password-guessing attempts.
- Consider email verification and a real "forgot password" flow (sends a one-time
  reset link by email — never emails or displays the actual password).
