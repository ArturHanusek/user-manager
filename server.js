/**
 * User Manager Server - Express API
 * Handles user registration, authentication, and container management
 */

import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { nanoid } from 'nanoid';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';

import { initDb, getDb } from './lib/db.js';
import {
  createUser,
  getUserByUsername,
  getUserByEmail,
  getUserById,
  validatePassword,
  verifyPassword,
  incrementFailedAttempts,
  resetFailedAttempts,
  isUserLocked,
  getAllUsers,
  userExists
} from './lib/auth.js';

const SESSION_SECRET = process.env.SESSION_SECRET || nanoid(32);
const SESSION_EXPIRY = parseInt(process.env.SESSION_EXPIRY || '86400000'); // 24 hours
const FIRST_USER_IS_ADMIN = process.env.FIRST_USER_IS_ADMIN !== 'false';

// Pending registrations (in-memory for simplicity)
const pendingRegistrations = new Map();
const pendingLogins = new Map();

/**
 * Create and configure Express app
 */
export async function createApp() {
  // Initialize database
  initDb();

  const app = express();

  // Middleware
  app.use(express.json());
  app.use(cookieParser());

  // Session configuration
  app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: SESSION_EXPIRY
    }
  }));

  // Rate limiting for auth endpoints
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    message: { error: 'Too many requests, please try again later' }
  });

  // ==========================================
  // Auth Routes
  // ==========================================

  /**
   * GET /api/auth/status - Check authentication status
   */
  app.get('/api/auth/status', (req, res) => {
    const needsSetup = !userExists();
    const authenticated = !!req.session?.userId;
    const user = authenticated ? getUserById(req.session.userId) : null;

    res.json({
      needsSetup,
      authenticated,
      user: user ? {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      } : null
    });
  });

  /**
   * POST /api/auth/register - Start registration (returns QR code for 2FA)
   */
  app.post('/api/auth/register', async (req, res) => {
    try {
      const { username, email, password } = req.body;

      // Validate required fields
      if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required' });
      }

      // Validate password
      const validation = validatePassword(password);
      if (!validation.valid) {
        return res.status(400).json({ error: 'Invalid password: ' + validation.errors.join(', ') });
      }

      // Check for duplicate username
      if (getUserByUsername(username)) {
        return res.status(400).json({ error: 'Username already exists' });
      }

      // Check for duplicate email
      if (getUserByEmail(email)) {
        return res.status(400).json({ error: 'Email already exists' });
      }

      // Generate TOTP secret
      const secret = authenticator.generateSecret();

      // Generate QR code
      const otpauth = authenticator.keyuri(username, 'UserManager', secret);
      const qrCode = await QRCode.toDataURL(otpauth);

      // Determine if first user (admin)
      const isAdmin = FIRST_USER_IS_ADMIN && !userExists();

      // Store pending registration
      pendingRegistrations.set(username, {
        username,
        email,
        password,
        secret,
        isAdmin,
        createdAt: Date.now()
      });

      // Clean up old pending registrations (after 10 minutes)
      setTimeout(() => {
        pendingRegistrations.delete(username);
      }, 10 * 60 * 1000);

      res.json({
        success: true,
        qrCode,
        secret,
        isAdmin
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  /**
   * POST /api/auth/register/complete - Complete registration with TOTP verification
   */
  app.post('/api/auth/register/complete', async (req, res) => {
    try {
      const { username, totpCode } = req.body;

      const pending = pendingRegistrations.get(username);
      if (!pending) {
        return res.status(400).json({ error: 'No pending registration found' });
      }

      // Verify TOTP
      const isValid = authenticator.verify({ token: totpCode, secret: pending.secret });
      if (!isValid) {
        return res.status(400).json({ error: 'Invalid verification code' });
      }

      // Generate backup codes
      const backupCodes = Array.from({ length: 10 }, () =>
        `${nanoid(4)}-${nanoid(4)}-${nanoid(4)}`
      );

      // Create user
      const userId = await createUser({
        username: pending.username,
        email: pending.email,
        password: pending.password,
        role: pending.isAdmin ? 'admin' : 'user',
        totpSecret: pending.secret,
        backupCodes
      });

      // Clean up pending registration
      pendingRegistrations.delete(username);

      // Create session
      req.session.userId = userId;

      res.json({
        success: true,
        userId,
        backupCodes
      });
    } catch (error) {
      console.error('Registration completion error:', error);
      res.status(500).json({ error: 'Registration completion failed' });
    }
  });

  /**
   * POST /api/auth/login - Login (first step)
   */
  app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
      const { username, password, totpCode } = req.body;

      // Find user
      const user = getUserByUsername(username);
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Check if locked
      if (isUserLocked(user)) {
        return res.status(423).json({
          error: 'Account locked due to too many failed attempts',
          lockedUntil: user.locked_until
        });
      }

      // Verify password
      const passwordValid = await verifyPassword(password, user.password_hash);
      if (!passwordValid) {
        incrementFailedAttempts(user.id);
        const updatedUser = getUserById(user.id);
        const attemptsRemaining = 5 - updatedUser.failed_attempts;

        return res.status(401).json({
          error: 'Invalid credentials',
          attemptsRemaining: Math.max(0, attemptsRemaining)
        });
      }

      // If TOTP provided, verify and complete login
      if (totpCode && user.totp_secret) {
        const totpValid = authenticator.verify({ token: totpCode, secret: user.totp_secret });
        if (!totpValid) {
          return res.status(401).json({ error: 'Invalid verification code' });
        }

        // Reset failed attempts and create session
        resetFailedAttempts(user.id);
        req.session.userId = user.id;

        return res.json({
          success: true,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
          }
        });
      }

      // Store pending login for 2FA
      const loginToken = nanoid();
      pendingLogins.set(loginToken, {
        userId: user.id,
        createdAt: Date.now()
      });

      // Clean up after 5 minutes
      setTimeout(() => {
        pendingLogins.delete(loginToken);
      }, 5 * 60 * 1000);

      // Store token in session for 2FA step
      req.session.pendingLogin = loginToken;

      res.json({
        requiresTwoFactor: true,
        loginToken
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  /**
   * POST /api/auth/verify-2fa - Complete login with 2FA
   */
  app.post('/api/auth/verify-2fa', async (req, res) => {
    try {
      const { code } = req.body;
      const loginToken = req.session?.pendingLogin;

      if (!loginToken) {
        return res.status(401).json({ error: 'No pending login session' });
      }

      const pending = pendingLogins.get(loginToken);
      if (!pending) {
        return res.status(401).json({ error: 'Login session expired' });
      }

      const user = getUserById(pending.userId);
      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }

      // Verify TOTP
      const isValid = authenticator.verify({ token: code, secret: user.totp_secret });
      if (!isValid) {
        return res.status(401).json({ error: 'Invalid verification code' });
      }

      // Clean up and create session
      pendingLogins.delete(loginToken);
      delete req.session.pendingLogin;
      resetFailedAttempts(user.id);
      req.session.userId = user.id;

      res.json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        }
      });
    } catch (error) {
      console.error('2FA verification error:', error);
      res.status(500).json({ error: '2FA verification failed' });
    }
  });

  /**
   * POST /api/auth/logout - Logout
   */
  app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Logout failed' });
      }
      res.json({ success: true });
    });
  });

  // ==========================================
  // Auth Middleware
  // ==========================================

  function requireAuth(req, res, next) {
    if (!req.session?.userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.user = getUserById(req.session.userId);
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  }

  function requireAdmin(req, res, next) {
    if (req.user?.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  }

  // ==========================================
  // User Routes (authenticated)
  // ==========================================

  app.get('/api/user/apps', requireAuth, (req, res) => {
    const db = getDb();
    const apps = db.prepare('SELECT * FROM containers WHERE user_id = ?').all(req.user.id);
    res.json({ apps });
  });

  // ==========================================
  // Admin Routes
  // ==========================================

  app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
    const users = getAllUsers();
    res.json({ users });
  });

  return app;
}

// Start server if run directly
const isMainModule = process.argv[1]?.endsWith('server.js');
if (isMainModule) {
  const port = process.env.PORT || 3000;
  const app = await createApp();
  app.listen(port, () => {
    console.log(`User Manager running on port ${port}`);
  });
}
