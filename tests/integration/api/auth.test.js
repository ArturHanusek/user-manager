/**
 * Authentication API integration tests (TDD)
 * Tests for /api/auth/* endpoints
 */

import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../../server.js';
import { createUser } from '../../../lib/auth.js';

let app;

beforeEach(async () => {
  app = await createApp();
});

describe('Auth API', () => {
  describe('GET /api/auth/status', () => {
    it('should return needsSetup: true when no users exist', async () => {
      const res = await request(app)
        .get('/api/auth/status')
        .expect(200);

      expect(res.body.needsSetup).toBe(true);
      expect(res.body.authenticated).toBe(false);
    });

    it('should return needsSetup: false when users exist', async () => {
      await createUser({
        username: 'admin',
        email: 'admin@example.com',
        password: 'ValidPassword123!'
      });

      const res = await request(app)
        .get('/api/auth/status')
        .expect(200);

      expect(res.body.needsSetup).toBe(false);
    });
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'ValidPassword123!'
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.qrCode).toBeDefined();
      expect(res.body.secret).toBeDefined();
    });

    it('should reject registration with weak password', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'weak'
        })
        .expect(400);

      expect(res.body.error).toContain('password');
    });

    it('should reject duplicate username', async () => {
      await createUser({
        username: 'existing',
        email: 'existing@example.com',
        password: 'ValidPassword123!'
      });

      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'existing',
          email: 'new@example.com',
          password: 'ValidPassword123!'
        })
        .expect(400);

      expect(res.body.error.toLowerCase()).toContain('username');
    });

    it('should reject duplicate email', async () => {
      await createUser({
        username: 'existing',
        email: 'same@example.com',
        password: 'ValidPassword123!'
      });

      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'newuser',
          email: 'same@example.com',
          password: 'ValidPassword123!'
        })
        .expect(400);

      expect(res.body.error.toLowerCase()).toContain('email');
    });

    it('should make first user an admin', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'firstuser',
          email: 'first@example.com',
          password: 'ValidPassword123!'
        })
        .expect(200);

      expect(res.body.isAdmin).toBe(true);
    });
  });

  describe('POST /api/auth/register/complete', () => {
    it('should complete registration with valid TOTP', async () => {
      // First start registration
      const registerRes = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'ValidPassword123!'
        });

      // For testing, we'll need to generate a valid TOTP
      // This test verifies the endpoint structure
      const res = await request(app)
        .post('/api/auth/register/complete')
        .send({
          username: 'newuser',
          totpCode: '123456' // Invalid code - should fail
        })
        .expect(400);

      expect(res.body.error).toBeDefined();
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      await createUser({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidPassword123!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      });
    });

    it('should return requiresTwoFactor for valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'ValidPassword123!'
        })
        .expect(200);

      expect(res.body.requiresTwoFactor).toBe(true);
    });

    it('should reject invalid username', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'nonexistent',
          password: 'ValidPassword123!'
        })
        .expect(401);

      expect(res.body.error).toContain('Invalid');
    });

    it('should reject invalid password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'WrongPassword123!'
        })
        .expect(401);

      expect(res.body.error).toContain('Invalid');
    });

    it('should track failed login attempts', async () => {
      await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'WrongPassword123!'
        });

      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'WrongPassword123!'
        })
        .expect(401);

      expect(res.body.attemptsRemaining).toBeDefined();
    });

    it('should lock account after max failed attempts', async () => {
      // Attempt 5 failed logins
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/auth/login')
          .send({
            username: 'testuser',
            password: 'WrongPassword123!'
          });
      }

      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'ValidPassword123!'
        })
        .expect(423);

      expect(res.body.error).toContain('locked');
      expect(res.body.lockedUntil).toBeDefined();
    });
  });

  describe('POST /api/auth/verify-2fa', () => {
    it('should require pending auth session', async () => {
      const res = await request(app)
        .post('/api/auth/verify-2fa')
        .send({
          code: '123456'
        })
        .expect(401);

      expect(res.body.error).toContain('session');
    });
  });

  describe('POST /api/auth/logout', () => {
    it('should destroy session on logout', async () => {
      const res = await request(app)
        .post('/api/auth/logout')
        .expect(200);

      expect(res.body.success).toBe(true);
    });
  });
});

describe('Protected Routes', () => {
  it('should reject unauthenticated requests to /api/user/*', async () => {
    app = await createApp();

    const res = await request(app)
      .get('/api/user/apps')
      .expect(401);

    expect(res.body.error).toContain('Unauthorized');
  });

  it('should reject unauthenticated requests to /api/admin/*', async () => {
    app = await createApp();

    const res = await request(app)
      .get('/api/admin/users')
      .expect(401);

    expect(res.body.error).toContain('Unauthorized');
  });
});
