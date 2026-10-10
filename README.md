# Secure Login System

A secure login web app built with Express, SQL.js, bcryptjs, sessions, and optional TOTP-based two-factor authentication.

## Features

- User registration and login with bcryptjs password hashing
- SQL injection protection through parameterized SQL statements
- Server-side validation with Zod
- Session-based authentication with logout
- Rate limiting on registration and login
- Optional 2FA using authenticator apps
- Secure cookie settings and Helmet security headers

## Requirements

- Node.js 18 or newer
- npm

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create your environment file:

   ```bash
   copy .env.example .env
   ```

3. Set a strong `SESSION_SECRET` value in `.env`.

4. Start the app:

   ```bash
   npm start
   ```

5. Open `http://localhost:3000` in your browser.

## Notes

- Passwords are stored as bcrypt hashes.
- All database access uses prepared statements.
- When 2FA is enabled, sign in requires a 6-digit code from an authenticator app.
- The database file is stored locally in `data/secure-login-system.sqlite`.

## Scripts

- `npm start` runs the server.
- `npm run dev` starts the server with Node watch mode.

# Secure Login System

A security-focused authentication platform built with Express.js, SQL.js,
bcryptjs, sessions, Zod validation, rate limiting, and optional TOTP
two-factor authentication.

## Features

- User registration and login
- bcrypt password hashing
- Parameterized SQL queries
- SQL injection protection
- Server-side validation with Zod
- Session-based authentication
- Secure logout
- Login and registration rate limiting
- Optional TOTP-based 2FA
- Secure HTTP cookies
- Helmet security headers

## Tech Stack

- Node.js
- Express.js
- SQL.js / SQLite
- bcryptjs
- Zod
- express-session
- Helmet
- TOTP / authenticator apps

## Security

This project demonstrates practical web authentication security,
including password hashing, input validation, parameterized database
queries, session management, rate limiting, secure cookies, and
two-factor authentication.

## Roadmap

- [ ] Password reset
- [ ] Email verification
- [ ] Account lockout detection
- [ ] Security event logging
- [ ] Admin security dashboard
- [ ] API authentication
- [ ] Security audit/testing tools

## Installation

### Requirements

- Node.js 18+
- npm

### Setup

```bash
npm install