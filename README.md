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
