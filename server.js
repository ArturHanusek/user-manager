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
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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

import {
  initDocker,
  createContainer,
  startContainer,
  stopContainer,
  removeContainer,
  getContainerStatus,
  listUserContainers
} from './lib/docker.js';

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

  app.get('/api/user/apps', requireAuth, async (req, res) => {
    try {
      const apps = await listUserContainers(req.user.id);
      res.json({ apps });
    } catch (error) {
      console.error('Error fetching apps:', error);
      res.status(500).json({ error: 'Failed to fetch apps' });
    }
  });

  /**
   * POST /api/user/apps - Create a new container
   */
  app.post('/api/user/apps', requireAuth, async (req, res) => {
    try {
      const { appType, subdomain, cpuLimit, memoryLimit } = req.body;

      if (!appType || !subdomain) {
        return res.status(400).json({ error: 'appType and subdomain are required' });
      }

      const container = await createContainer({
        userId: req.user.id,
        appType,
        subdomain,
        cpuLimit,
        memoryLimit
      });

      res.status(201).json({ container });
    } catch (error) {
      console.error('Error creating container:', error);
      if (error.message.includes('not found')) {
        return res.status(400).json({ error: error.message });
      }
      if (error.message.includes('exists')) {
        return res.status(400).json({ error: error.message });
      }
      res.status(500).json({ error: 'Failed to create container' });
    }
  });

  /**
   * POST /api/user/apps/:id/start - Start a container
   */
  app.post('/api/user/apps/:id/start', requireAuth, async (req, res) => {
    try {
      const containerId = parseInt(req.params.id);

      // Verify container belongs to user
      const db = getDb();
      const container = db.prepare('SELECT * FROM containers WHERE id = ?').get(containerId);

      if (!container) {
        return res.status(404).json({ error: 'Container not found' });
      }

      if (container.user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }

      const result = await startContainer(containerId);
      res.json(result);
    } catch (error) {
      console.error('Error starting container:', error);
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      res.status(500).json({ error: 'Failed to start container' });
    }
  });

  /**
   * POST /api/user/apps/:id/stop - Stop a container
   */
  app.post('/api/user/apps/:id/stop', requireAuth, async (req, res) => {
    try {
      const containerId = parseInt(req.params.id);

      // Verify container belongs to user
      const db = getDb();
      const container = db.prepare('SELECT * FROM containers WHERE id = ?').get(containerId);

      if (!container) {
        return res.status(404).json({ error: 'Container not found' });
      }

      if (container.user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }

      const result = await stopContainer(containerId);
      res.json(result);
    } catch (error) {
      console.error('Error stopping container:', error);
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      res.status(500).json({ error: 'Failed to stop container' });
    }
  });

  /**
   * DELETE /api/user/apps/:id - Delete a container
   */
  app.delete('/api/user/apps/:id', requireAuth, async (req, res) => {
    try {
      const containerId = parseInt(req.params.id);

      // Verify container belongs to user
      const db = getDb();
      const container = db.prepare('SELECT * FROM containers WHERE id = ?').get(containerId);

      if (!container) {
        return res.status(404).json({ error: 'Container not found' });
      }

      if (container.user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }

      const result = await removeContainer(containerId);
      res.json(result);
    } catch (error) {
      console.error('Error deleting container:', error);
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      res.status(500).json({ error: 'Failed to delete container' });
    }
  });

  /**
   * GET /api/user/apps/:id/status - Get container status
   */
  app.get('/api/user/apps/:id/status', requireAuth, async (req, res) => {
    try {
      const containerId = parseInt(req.params.id);

      // Verify container belongs to user
      const db = getDb();
      const container = db.prepare('SELECT * FROM containers WHERE id = ?').get(containerId);

      if (!container) {
        return res.status(404).json({ error: 'Container not found' });
      }

      if (container.user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }

      const status = await getContainerStatus(containerId);
      res.json(status);
    } catch (error) {
      console.error('Error getting container status:', error);
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      res.status(500).json({ error: 'Failed to get container status' });
    }
  });

  // ==========================================
  // Admin Routes
  // ==========================================

  app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
    const users = getAllUsers();
    res.json({ users });
  });

  /**
   * GET /api/admin/containers - List all containers (admin only)
   */
  app.get('/api/admin/containers', requireAuth, requireAdmin, (req, res) => {
    try {
      const db = getDb();
      const containers = db.prepare(`
        SELECT c.*, u.username as owner_username
        FROM containers c
        LEFT JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
      `).all();
      res.json({ containers });
    } catch (error) {
      console.error('Error fetching all containers:', error);
      res.status(500).json({ error: 'Failed to fetch containers' });
    }
  });

  /**
   * GET /api/admin/app-types - List all app types
   */
  app.get('/api/admin/app-types', requireAuth, requireAdmin, (req, res) => {
    try {
      const db = getDb();
      const appTypes = db.prepare('SELECT * FROM app_types ORDER BY name').all();
      res.json({ appTypes });
    } catch (error) {
      console.error('Error fetching app types:', error);
      res.status(500).json({ error: 'Failed to fetch app types' });
    }
  });

  /**
   * POST /api/admin/app-types - Create a new app type
   */
  app.post('/api/admin/app-types', requireAuth, requireAdmin, (req, res) => {
    try {
      const { name, displayName, dockerImage, defaultPort, description } = req.body;

      if (!name || !dockerImage || !defaultPort) {
        return res.status(400).json({ error: 'name, dockerImage, and defaultPort are required' });
      }

      const db = getDb();

      // Check if app type already exists
      const existing = db.prepare('SELECT id FROM app_types WHERE name = ?').get(name);
      if (existing) {
        return res.status(400).json({ error: 'App type already exists' });
      }

      const result = db.prepare(`
        INSERT INTO app_types (name, display_name, docker_image, default_port, description, enabled)
        VALUES (?, ?, ?, ?, ?, 1)
      `).run(name, displayName || name, dockerImage, defaultPort, description || '');

      const appType = db.prepare('SELECT * FROM app_types WHERE id = ?').get(result.lastInsertRowid);
      res.status(201).json({ appType });
    } catch (error) {
      console.error('Error creating app type:', error);
      res.status(500).json({ error: 'Failed to create app type' });
    }
  });

  // ==========================================
  // Static Files (Production)
  // ==========================================

  if (process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'test') {
    const distPath = join(__dirname, 'dist');
    app.use(express.static(distPath));

    // SPA fallback - serve index.html for all non-API routes
    app.get('*', (req, res) => {
      res.sendFile(join(distPath, 'index.html'));
    });
  }

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
