/**
 * Authentication module - User management and password handling
 * Handles user CRUD, password validation/hashing, and account lockout
 */

import bcrypt from 'bcrypt';
import { getDb } from './db.js';

const SALT_ROUNDS = 10;
const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5');
const LOCKOUT_DURATION = parseInt(process.env.LOCKOUT_DURATION || '900000'); // 15 minutes

/**
 * Validate password against security requirements
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validatePassword(password) {
  const errors = [];

  if (password.length < 12) {
    errors.push('Password must be at least 12 characters');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain a lowercase letter');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain an uppercase letter');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain a number');
  }
  if (!/[!@#$%^&*()_+\-=\[\]{}';:"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain a special character');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Create a new user
 * @param {{ username: string, email: string, password: string, role?: string, totpSecret?: string, backupCodes?: string[] }}
 * @returns {Promise<number>} User ID
 */
export async function createUser({ username, email, password, role = 'user', totpSecret = null, backupCodes = null }) {
  // Validate password
  const validation = validatePassword(password);
  if (!validation.valid) {
    throw new Error('Invalid password: ' + validation.errors.join(', '));
  }

  // Hash password
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO users (username, email, password_hash, role, totp_secret, backup_codes)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    username,
    email,
    passwordHash,
    role,
    totpSecret,
    backupCodes ? JSON.stringify(backupCodes) : null
  );

  return result.lastInsertRowid;
}

/**
 * Get user by username
 * @returns {object|null} User object or null if not found
 */
export function getUserByUsername(username) {
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  return user || null;
}

/**
 * Get user by email
 * @returns {object|null} User object or null if not found
 */
export function getUserByEmail(email) {
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  return user || null;
}

/**
 * Get user by ID
 * @returns {object|null} User object or null if not found
 */
export function getUserById(id) {
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  return user || null;
}

/**
 * Verify password against hash
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

/**
 * Update user role
 */
export function updateUserRole(userId, role) {
  const db = getDb();
  db.prepare(`
    UPDATE users SET role = ?, updated_at = strftime('%s', 'now')
    WHERE id = ?
  `).run(role, userId);
}

/**
 * Increment failed login attempts and lock if necessary
 */
export function incrementFailedAttempts(userId) {
  const db = getDb();
  const user = getUserById(userId);

  if (!user) {
    return; // User not found, nothing to increment
  }

  const newAttempts = (user.failed_attempts || 0) + 1;
  let lockedUntil = null;

  if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
    lockedUntil = Date.now() + LOCKOUT_DURATION;
  }

  db.prepare(`
    UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = strftime('%s', 'now')
    WHERE id = ?
  `).run(newAttempts, lockedUntil, userId);
}

/**
 * Reset failed login attempts
 */
export function resetFailedAttempts(userId) {
  const db = getDb();
  db.prepare(`
    UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = strftime('%s', 'now')
    WHERE id = ?
  `).run(userId);
}

/**
 * Check if user account is locked
 * @returns {boolean}
 */
export function isUserLocked(user) {
  if (!user.locked_until) {
    return false;
  }
  return user.locked_until > Date.now();
}

/**
 * Delete user by ID
 */
export function deleteUser(userId) {
  const db = getDb();
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);
}

/**
 * Get all users (without sensitive data)
 * @returns {object[]}
 */
export function getAllUsers() {
  const db = getDb();
  return db.prepare(`
    SELECT id, username, email, role, email_verified, failed_attempts, locked_until, created_at, updated_at
    FROM users
    ORDER BY id
  `).all();
}

/**
 * Check if any user exists in the database
 * @returns {boolean}
 */
export function userExists() {
  const db = getDb();
  const result = db.prepare('SELECT COUNT(*) as count FROM users').get();
  return result.count > 0;
}
