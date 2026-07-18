const path = require('path');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const express = require('express');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const helmet = require('helmet');
const QRCode = require('qrcode');
const { authenticator } = require('otplib');
const { z } = require('zod');
const { initializeDatabase } = require('./db');

dotenv.config();

authenticator.options = {
  step: 30,
  window: 1,
};

const appName = 'Secure Login System';
const port = Number(process.env.PORT || 3000);
const sessionSecret = process.env.SESSION_SECRET || 'dev-only-session-secret-change-me';

const registerSchema = z.object({
  email: z.string().trim().email('Enter a valid email address.'),
  password: z.string().min(12, 'Password must be at least 12 characters long.'),
  confirmPassword: z.string().min(12, 'Confirm your password.'),
});

const loginSchema = z.object({
  email: z.string().trim().email('Enter a valid email address.'),
  password: z.string().min(1, 'Password is required.'),
});

const tokenSchema = z.object({
  token: z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit authenticator code.'),
});

const disableTwoFactorSchema = z.object({
  password: z.string().min(1, 'Password is required.'),
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function flashToLocals(req, res, next) {
  res.locals.appName = appName;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
}

function redirectWithFlash(req, res, pathName, type, message) {
  setFlash(req, type, message);
  return res.redirect(pathName);
}

function validateForm(schema, body) {
  const result = schema.safeParse(body);
  if (!result.success) {
    return {
      ok: false,
      message: result.error.issues[0]?.message || 'Check the form and try again.',
    };
  }

  return { ok: true, data: result.data };
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(error => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

function requireAuth(database) {
  return (req, res, next) => {
    if (!req.session.userId) {
      return redirectWithFlash(req, res, '/login', 'error', 'Please sign in to continue.');
    }

    const currentUser = database.findUserById(req.session.userId);
    if (!currentUser) {
      req.session.destroy(() => {});
      return redirectWithFlash(req, res, '/login', 'error', 'Your session expired. Please sign in again.');
    }

    req.currentUser = currentUser;
    res.locals.currentUser = currentUser;
    next();
  };
}

function requirePendingTwoFactor(database) {
  return (req, res, next) => {
    if (!req.session.pendingTwoFactorUserId) {
      return redirectWithFlash(req, res, '/login', 'error', 'Please sign in again.');
    }

    const pendingUser = database.findUserById(req.session.pendingTwoFactorUserId);
    if (!pendingUser) {
      req.session.destroy(() => {});
      return redirectWithFlash(req, res, '/login', 'error', 'Your sign in session expired.');
    }

    req.pendingUser = pendingUser;
    next();
  };
}

async function loginUser(req, userId) {
  await regenerateSession(req);
  req.session.userId = userId;
}

async function startPendingTwoFactor(req, userId) {
  await regenerateSession(req);
  req.session.pendingTwoFactorUserId = userId;
}

async function bootstrap() {
  const database = await initializeDatabase();
  const app = express();

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  }));

  app.use(express.urlencoded({ extended: false }));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(session({
    name: 'secure-login.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 4,
    },
    store: new MemoryStore({
      checkPeriod: 1000 * 60 * 60,
    }),
  }));
  app.use(flashToLocals);

  app.use((req, res, next) => {
    res.locals.currentUser = null;
    if (req.session.userId) {
      const currentUser = database.findUserById(req.session.userId);
      if (!currentUser) {
        req.session.destroy(() => {});
        return redirectWithFlash(req, res, '/login', 'error', 'Your session expired. Please sign in again.');
      }

      req.currentUser = currentUser;
      res.locals.currentUser = currentUser;
    }

    next();
  });

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many attempts. Please wait a few minutes and try again.',
  });

  const formLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 25,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many submissions. Please wait a few minutes and try again.',
  });

  app.get('/', (req, res) => {
    if (req.session.userId) {
      return res.redirect('/dashboard');
    }

    return res.redirect('/login');
  });

  app.get('/register', (req, res) => {
    res.render('register', {
      pageTitle: 'Create Account',
      values: { email: '' },
      formError: null,
    });
  });

  app.post('/register', formLimiter, async (req, res) => {
    const values = { email: String(req.body.email || '') };
    const parsed = validateForm(registerSchema, req.body);

    if (!parsed.ok) {
      return res.status(400).render('register', {
        pageTitle: 'Create Account',
        values,
        formError: parsed.message,
      });
    }

    const { email, password, confirmPassword } = parsed.data;
    if (password !== confirmPassword) {
      return res.status(400).render('register', {
        pageTitle: 'Create Account',
        values: { email },
        formError: 'Passwords do not match.',
      });
    }

    if (database.findUserByEmail(email)) {
      return res.status(400).render('register', {
        pageTitle: 'Create Account',
        values: { email },
        formError: 'An account with that email already exists.',
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const createdUser = database.createUser({ email, passwordHash });
    await loginUser(req, createdUser.id);
    setFlash(req, 'success', 'Account created successfully.');
    return res.redirect('/dashboard');
  });

  app.get('/login', (req, res) => {
    res.render('login', {
      pageTitle: 'Sign In',
      values: { email: '' },
      formError: null,
    });
  });

  app.post('/login', loginLimiter, async (req, res) => {
    const values = { email: String(req.body.email || '') };
    const parsed = validateForm(loginSchema, req.body);

    if (!parsed.ok) {
      return res.status(400).render('login', {
        pageTitle: 'Sign In',
        values,
        formError: parsed.message,
      });
    }

    const { email, password } = parsed.data;
    const user = database.findUserByEmail(email);

    if (!user) {
      return res.status(400).render('login', {
        pageTitle: 'Sign In',
        values: { email },
        formError: 'Invalid email or password.',
      });
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatches) {
      return res.status(400).render('login', {
        pageTitle: 'Sign In',
        values: { email },
        formError: 'Invalid email or password.',
      });
    }

    if (user.twoFactorEnabled) {
      await startPendingTwoFactor(req, user.id);
      req.session.pendingTwoFactorRememberedEmail = user.email;
      return res.redirect('/2fa/verify');
    }

    await loginUser(req, user.id);
    setFlash(req, 'success', 'Signed in successfully.');
    return res.redirect('/dashboard');
  });

  app.get('/2fa/verify', requirePendingTwoFactor(database), (req, res) => {
    res.render('twofa-verify', {
      pageTitle: 'Two-Factor Verification',
      values: { token: '' },
      formError: null,
      email: req.pendingUser.email,
    });
  });

  app.post('/2fa/verify', loginLimiter, requirePendingTwoFactor(database), async (req, res) => {
    const parsed = validateForm(tokenSchema, req.body);
    if (!parsed.ok) {
      return res.status(400).render('twofa-verify', {
        pageTitle: 'Two-Factor Verification',
        values: { token: String(req.body.token || '') },
        formError: parsed.message,
        email: req.pendingUser.email,
      });
    }

    const { token } = parsed.data;
    const codeIsValid = authenticator.check(token, req.pendingUser.twoFactorSecret || '');
    if (!codeIsValid) {
      return res.status(400).render('twofa-verify', {
        pageTitle: 'Two-Factor Verification',
        values: { token },
        formError: 'Invalid authenticator code.',
        email: req.pendingUser.email,
      });
    }

    const userId = req.pendingUser.id;
    await loginUser(req, userId);
    delete req.session.pendingTwoFactorUserId;
    delete req.session.pendingTwoFactorRememberedEmail;
    setFlash(req, 'success', 'Two-factor verification passed.');
    return res.redirect('/dashboard');
  });

  app.get('/dashboard', requireAuth(database), (req, res) => {
    res.render('dashboard', {
      pageTitle: 'Dashboard',
    });
  });

  app.get('/2fa/setup', requireAuth(database), async (req, res) => {
    const currentUser = req.currentUser;
    if (currentUser.twoFactorEnabled) {
      return redirectWithFlash(req, res, '/dashboard', 'info', 'Two-factor authentication is already enabled.');
    }

    if (!req.session.twoFactorSetupSecret) {
      req.session.twoFactorSetupSecret = authenticator.generateSecret();
    }

    const secret = req.session.twoFactorSetupSecret;
    const otpauthUrl = authenticator.keyuri(currentUser.email, appName, secret);
    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);

    res.render('twofa-setup', {
      pageTitle: 'Enable Two-Factor Authentication',
      values: { token: '' },
      formError: null,
      qrCodeDataUrl,
      secret,
      email: currentUser.email,
    });
  });

  app.post('/2fa/setup', requireAuth(database), async (req, res) => {
    if (!req.session.twoFactorSetupSecret) {
      return redirectWithFlash(req, res, '/2fa/setup', 'error', 'Your setup session expired. Please start again.');
    }

    const parsed = validateForm(tokenSchema, req.body);
    const currentUser = req.currentUser;

    if (!parsed.ok) {
      const otpauthUrl = authenticator.keyuri(currentUser.email, appName, req.session.twoFactorSetupSecret);
      const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);
      return res.status(400).render('twofa-setup', {
        pageTitle: 'Enable Two-Factor Authentication',
        values: { token: String(req.body.token || '') },
        formError: parsed.message,
        qrCodeDataUrl,
        secret: req.session.twoFactorSetupSecret,
        email: currentUser.email,
      });
    }

    const { token } = parsed.data;
    const secret = req.session.twoFactorSetupSecret;
    const codeIsValid = authenticator.check(token, secret);

    if (!codeIsValid) {
      const otpauthUrl = authenticator.keyuri(currentUser.email, appName, secret);
      const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);
      return res.status(400).render('twofa-setup', {
        pageTitle: 'Enable Two-Factor Authentication',
        values: { token },
        formError: 'Invalid authenticator code.',
        qrCodeDataUrl,
        secret,
        email: currentUser.email,
      });
    }

    database.updateTwoFactor(currentUser.id, { secret, enabled: true });
    delete req.session.twoFactorSetupSecret;
    setFlash(req, 'success', 'Two-factor authentication is now enabled.');
    return res.redirect('/dashboard');
  });

  app.post('/2fa/disable', requireAuth(database), async (req, res) => {
    const parsed = validateForm(disableTwoFactorSchema, req.body);
    if (!parsed.ok) {
      return res.status(400).render('dashboard', {
        pageTitle: 'Dashboard',
        formError: parsed.message,
      });
    }

    const currentUser = req.currentUser;
    const passwordMatches = await bcrypt.compare(parsed.data.password, currentUser.passwordHash);
    if (!passwordMatches) {
      return res.status(400).render('dashboard', {
        pageTitle: 'Dashboard',
        formError: 'Password confirmation failed.',
      });
    }

    database.disableTwoFactor(currentUser.id);
    setFlash(req, 'success', 'Two-factor authentication has been disabled.');
    return res.redirect('/dashboard');
  });

  app.post('/logout', requireAuth(database), (req, res) => {
    req.session.destroy(() => {
      res.clearCookie('secure-login.sid');
      res.redirect('/login');
    });
  });

  app.use((req, res) => {
    res.status(404).render('login', {
      pageTitle: 'Page Not Found',
      values: { email: '' },
      formError: 'That page does not exist.',
    });
  });

  app.listen(port, () => {
    console.log(`${appName} running on http://localhost:${port}`);
  });
}

bootstrap().catch(error => {
  console.error('Failed to start the application:');
  console.error(error);
  process.exit(1);
});
