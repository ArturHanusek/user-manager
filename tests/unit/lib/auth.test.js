/**
 * Authentication module tests (TDD - Red/Green/Refactor)
 * Tests for user creation, password validation, login, and 2FA
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  createUser,
  getUserByUsername,
  getUserByEmail,
  getUserById,
  validatePassword,
  verifyPassword,
  updateUserRole,
  incrementFailedAttempts,
  resetFailedAttempts,
  isUserLocked,
  deleteUser,
  getAllUsers,
  userExists
} from '../../../lib/auth.js';

describe('Auth Module', () => {
  describe('Password Validation', () => {
    it('should reject passwords shorter than 12 characters', () => {
      const result = validatePassword('Short1!abc');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must be at least 12 characters');
    });

    it('should reject passwords without lowercase letters', () => {
      const result = validatePassword('NOLOWERCASE123!@#');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain a lowercase letter');
    });

    it('should reject passwords without uppercase letters', () => {
      const result = validatePassword('nouppercase123!@#');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain an uppercase letter');
    });

    it('should reject passwords without numbers', () => {
      const result = validatePassword('NoNumbersHere!@#');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain a number');
    });

    it('should reject passwords without special characters', () => {
      const result = validatePassword('NoSpecialChar123');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain a special character');
    });

    it('should accept valid passwords', () => {
      const result = validatePassword('ValidPassword123!');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('User Creation', () => {
    it('should create a user with valid data', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      expect(userId).toBeDefined();
      expect(typeof userId).toBe('number');
      expect(userId).toBeGreaterThan(0);
    });

    it('should hash the password', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const user = getUserById(userId);
      expect(user.password_hash).not.toBe('ValidPassword123!');
      expect(user.password_hash).toMatch(/^\$2[aby]\$/); // bcrypt prefix
    });

    it('should set default role to user', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const user = getUserById(userId);
      expect(user.role).toBe('user');
    });

    it('should reject duplicate username', async () => {
      await createUser({
        username: 'testuser',
        email: 'test1@example.com',
        password: 'ValidPassword123!'
      });

      await expect(
        createUser({
          username: 'testuser',
          email: 'test2@example.com',
          password: 'ValidPassword123!'
        })
      ).rejects.toThrow();
    });

    it('should reject duplicate email', async () => {
      await createUser({
        username: 'user1',
        email: 'same@example.com',
        password: 'ValidPassword123!'
      });

      await expect(
        createUser({
          username: 'user2',
          email: 'same@example.com',
          password: 'ValidPassword123!'
        })
      ).rejects.toThrow();
    });

    it('should reject invalid password', async () => {
      await expect(
        createUser({
          username: 'testuser',
          email: 'test@example.com',
          password: 'weak'
        })
      ).rejects.toThrow('Invalid password');
    });

    it('should create admin user when specified', async () => {
      const userId = await createUser({
        username: 'admin',
        email: 'admin@example.com',
        password: 'ValidPassword123!',
        role: 'admin'
      });

      const user = getUserById(userId);
      expect(user.role).toBe('admin');
    });

    it('should store TOTP secret when provided', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      });

      const user = getUserById(userId);
      expect(user.totp_secret).toBe('JBSWY3DPEHPK3PXP');
    });

    it('should store backup codes when provided', async () => {
      const backupCodes = ['code1', 'code2', 'code3'];
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!',
        backupCodes
      });

      const user = getUserById(userId);
      expect(JSON.parse(user.backup_codes)).toEqual(backupCodes);
    });
  });

  describe('User Retrieval', () => {
    beforeEach(async () => {
      await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });
    });

    it('should find user by username', () => {
      const user = getUserByUsername('testuser');
      expect(user).toBeDefined();
      expect(user.username).toBe('testuser');
    });

    it('should find user by email', () => {
      const user = getUserByEmail('test@example.com');
      expect(user).toBeDefined();
      expect(user.email).toBe('test@example.com');
    });

    it('should find user by id', async () => {
      const userId = await createUser({
        username: 'another',
        email: 'another@example.com',
        password: 'ValidPassword123!'
      });

      const user = getUserById(userId);
      expect(user).toBeDefined();
      expect(user.id).toBe(userId);
    });

    it('should return null for non-existent username', () => {
      const user = getUserByUsername('nonexistent');
      expect(user).toBeNull();
    });

    it('should return null for non-existent email', () => {
      const user = getUserByEmail('nonexistent@example.com');
      expect(user).toBeNull();
    });

    it('should return null for non-existent id', () => {
      const user = getUserById(99999);
      expect(user).toBeNull();
    });
  });

  describe('Password Verification', () => {
    it('should verify correct password', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const user = getUserById(userId);
      const isValid = await verifyPassword('ValidPassword123!', user.password_hash);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const user = getUserById(userId);
      const isValid = await verifyPassword('WrongPassword123!', user.password_hash);
      expect(isValid).toBe(false);
    });
  });

  describe('Account Lockout', () => {
    it('should track failed login attempts', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      incrementFailedAttempts(userId);
      incrementFailedAttempts(userId);

      const user = getUserById(userId);
      expect(user.failed_attempts).toBe(2);
    });

    it('should lock account after max failed attempts', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      // Attempt 5 failed logins (default max)
      for (let i = 0; i < 5; i++) {
        incrementFailedAttempts(userId);
      }

      const user = getUserById(userId);
      expect(isUserLocked(user)).toBe(true);
    });

    it('should not lock account before max attempts', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      for (let i = 0; i < 4; i++) {
        incrementFailedAttempts(userId);
      }

      const user = getUserById(userId);
      expect(isUserLocked(user)).toBe(false);
    });

    it('should reset failed attempts counter', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      incrementFailedAttempts(userId);
      incrementFailedAttempts(userId);
      resetFailedAttempts(userId);

      const user = getUserById(userId);
      expect(user.failed_attempts).toBe(0);
      expect(user.locked_until).toBeNull();
    });
  });

  describe('User Management', () => {
    it('should update user role', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      updateUserRole(userId, 'admin');

      const user = getUserById(userId);
      expect(user.role).toBe('admin');
    });

    it('should delete user', async () => {
      const userId = await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      deleteUser(userId);

      const user = getUserById(userId);
      expect(user).toBeNull();
    });

    it('should get all users', async () => {
      await createUser({
        username: 'user1',
        email: 'user1@example.com',
        password: 'ValidPassword123!'
      });
      await createUser({
        username: 'user2',
        email: 'user2@example.com',
        password: 'ValidPassword123!'
      });

      const users = getAllUsers();
      expect(users).toHaveLength(2);
      expect(users[0].username).toBe('user1');
      expect(users[1].username).toBe('user2');
    });

    it('should check if any user exists', async () => {
      expect(userExists()).toBe(false);

      await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      expect(userExists()).toBe(true);
    });

    it('should not expose password hash in getAllUsers', async () => {
      await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const users = getAllUsers();
      expect(users[0].password_hash).toBeUndefined();
    });
  });
});
