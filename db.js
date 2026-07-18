const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const dataDirectory = path.join(__dirname, 'data');
const databaseFile = path.join(dataDirectory, 'secure-login-system.sqlite');

function normalizeEmail(email) {
  return String(email).trim().toLowerCase();
}

function mapUserRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    email: row.email,
    passwordHash: row.password_hash,
    twoFactorSecret: row.two_factor_secret,
    twoFactorEnabled: Boolean(row.two_factor_enabled),
    createdAt: row.created_at,
  };
}

function readSingleRow(database, sql, params = []) {
  const statement = database.prepare(sql);

  try {
    statement.bind(params);
    if (!statement.step()) {
      return null;
    }

    return statement.getAsObject();
  } finally {
    statement.free();
  }
}

function writeDatabase(database) {
  fs.mkdirSync(dataDirectory, { recursive: true });
  const data = database.export();
  fs.writeFileSync(databaseFile, Buffer.from(data));
}

function ensureSchema(database) {
  database.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      two_factor_secret TEXT,
      two_factor_enabled INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  writeDatabase(database);
}

async function initializeDatabase() {
  const sqlJsDirectory = path.dirname(require.resolve('sql.js/dist/sql-wasm.wasm'));
  const SQL = await initSqlJs({
    locateFile: fileName => path.join(sqlJsDirectory, fileName),
  });

  let database;
  if (fs.existsSync(databaseFile)) {
    const fileBuffer = fs.readFileSync(databaseFile);
    database = new SQL.Database(new Uint8Array(fileBuffer));
  } else {
    database = new SQL.Database();
  }

  ensureSchema(database);

  return {
    findUserById(userId) {
      const row = readSingleRow(database, 'SELECT * FROM users WHERE id = ?', [userId]);
      return mapUserRow(row);
    },

    findUserByEmail(email) {
      const normalizedEmail = normalizeEmail(email);
      const row = readSingleRow(database, 'SELECT * FROM users WHERE email = ?', [normalizedEmail]);
      return mapUserRow(row);
    },

    createUser({ email, passwordHash }) {
      const normalizedEmail = normalizeEmail(email);
      const statement = database.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)');

      try {
        statement.run([normalizedEmail, passwordHash]);
      } finally {
        statement.free();
      }

      writeDatabase(database);
      return this.findUserByEmail(normalizedEmail);
    },

    updateTwoFactor(userId, { secret, enabled }) {
      const statement = database.prepare(
        'UPDATE users SET two_factor_secret = ?, two_factor_enabled = ? WHERE id = ?'
      );

      try {
        statement.run([secret, enabled ? 1 : 0, userId]);
      } finally {
        statement.free();
      }

      writeDatabase(database);
      return this.findUserById(userId);
    },

    disableTwoFactor(userId) {
      return this.updateTwoFactor(userId, { secret: null, enabled: false });
    },
  };
}

module.exports = {
  initializeDatabase,
};
