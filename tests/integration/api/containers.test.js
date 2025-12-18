/**
 * Integration Tests for Container API Endpoints (TDD)
 */

import { describe, it, expect, beforeEach, beforeAll, afterAll, vi } from 'vitest';
import request from 'supertest';
import { createApp } from '../../../server.js';
import { resetDb, getDb, closeDb } from '../../../lib/db.js';
import { createUser } from '../../../lib/auth.js';
import { authenticator } from 'otplib';

// Mock dockerode
vi.mock('dockerode', () => {
  const mockContainer = {
    id: 'container123abc',
    inspect: vi.fn().mockResolvedValue({
      Id: 'container123abc',
      State: { Running: true, Status: 'running' },
      Config: { Image: 'webterminal-user:latest' },
      NetworkSettings: { Ports: { '9999/tcp': [{ HostPort: '10001' }] } }
    }),
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn().mockResolvedValue(undefined),
    remove: vi.fn().mockResolvedValue(undefined),
    logs: vi.fn().mockResolvedValue(Buffer.from('container logs'))
  };

  const mockDocker = {
    createContainer: vi.fn().mockResolvedValue(mockContainer),
    getContainer: vi.fn().mockReturnValue(mockContainer),
    listContainers: vi.fn().mockResolvedValue([]),
    pull: vi.fn().mockImplementation((image, callback) => {
      callback(null, { pipe: vi.fn() });
    })
  };

  return {
    default: vi.fn(() => mockDocker)
  };
});

describe('Container API', () => {
  let app;
  let testUserId;
  let totpSecret;
  let userAgent;  // supertest agent with session cookies
  let adminUserId;
  let adminTotpSecret;
  let adminAgent;  // supertest agent with admin session cookies

  /**
   * Seed app_types table with test data
   */
  function seedAppTypes() {
    const db = getDb();
    db.prepare(`
      INSERT INTO app_types (name, display_name, docker_image, default_port, description, enabled)
      VALUES ('web-terminal', 'Web Terminal', 'webterminal-user:latest', 9999, 'Web-based terminal', 1)
    `).run();
  }

  /**
   * Login helper that returns an agent with authenticated session
   */
  async function loginUser(username, password, secret) {
    const agent = request.agent(app);

    // First login step - sends credentials
    const loginRes = await agent
      .post('/api/auth/login')
      .send({ username, password });

    // If 2FA required, complete it
    if (loginRes.body.requiresTwoFactor) {
      const code = authenticator.generate(secret);
      await agent
        .post('/api/auth/verify-2fa')
        .send({ code });
    }

    return agent;
  }

  afterAll(async () => {
    await closeDb();
  });

  beforeEach(async () => {
    await resetDb();
    seedAppTypes();

    // Create fresh app for each test to ensure clean session store
    app = await createApp();

    // Create regular test user
    totpSecret = authenticator.generateSecret();
    testUserId = await createUser({
      username: 'testuser',
      email: 'test@example.com',
      password: 'ValidPassword123!',
      role: 'user',
      totpSecret,
      backupCodes: ['backup1', 'backup2']
    });

    // Create admin user
    adminTotpSecret = authenticator.generateSecret();
    adminUserId = await createUser({
      username: 'adminuser',
      email: 'admin@example.com',
      password: 'AdminPassword123!',
      role: 'admin',
      totpSecret: adminTotpSecret,
      backupCodes: ['admin-backup1']
    });

    // Login and get session agents
    userAgent = await loginUser('testuser', 'ValidPassword123!', totpSecret);
    adminAgent = await loginUser('adminuser', 'AdminPassword123!', adminTotpSecret);
  });

  describe('GET /api/user/apps', () => {
    it('should return empty array when user has no containers', async () => {
      const res = await userAgent.get('/api/user/apps');

      expect(res.status).toBe(200);
      expect(res.body.apps).toEqual([]);
    });

    it('should return 401 when not authenticated', async () => {
      const res = await request(app).get('/api/user/apps');

      expect(res.status).toBe(401);
    });
  });

  describe('POST /api/user/apps', () => {
    it('should create a new container for authenticated user', async () => {
      const res = await userAgent
        .post('/api/user/apps')
        .send({
          appType: 'web-terminal',
          subdomain: 'testuser-terminal'
        });

      expect(res.status).toBe(201);
      expect(res.body.container).toBeDefined();
      expect(res.body.container.subdomain).toBe('testuser-terminal');
    });

    it('should return 400 for invalid app type', async () => {
      const res = await userAgent
        .post('/api/user/apps')
        .send({
          appType: 'invalid-type',
          subdomain: 'test-subdomain'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/app type/i);
    });

    it('should return 400 for duplicate subdomain', async () => {
      // Create first container
      await userAgent
        .post('/api/user/apps')
        .send({
          appType: 'web-terminal',
          subdomain: 'duplicate-subdomain'
        });

      // Try to create second with same subdomain
      const res = await userAgent
        .post('/api/user/apps')
        .send({
          appType: 'web-terminal',
          subdomain: 'duplicate-subdomain'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/subdomain/i);
    });

    it('should return 401 when not authenticated', async () => {
      const res = await request(app)
        .post('/api/user/apps')
        .send({
          appType: 'web-terminal',
          subdomain: 'test-subdomain'
        });

      expect(res.status).toBe(401);
    });
  });

  describe('POST /api/user/apps/:id/start', () => {
    it('should start a container', async () => {
      // Create container first
      const createRes = await userAgent
        .post('/api/user/apps')
        .send({
          appType: 'web-terminal',
          subdomain: 'start-test'
        });

      const containerId = createRes.body.container.id;

      // Start it
      const res = await userAgent.post(`/api/user/apps/${containerId}/start`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should return 404 for non-existent container', async () => {
      const res = await userAgent.post('/api/user/apps/99999/start');

      expect(res.status).toBe(404);
    });

    it('should return 403 when trying to start another users container', async () => {
      // Create container as test user
      const createRes = await userAgent
        .post('/api/user/apps')
        .send({
          appType: 'web-terminal',
          subdomain: 'other-user-container'
        });

      const containerId = createRes.body.container.id;

      // Create another user and try to start the container
      const otherTotpSecret = authenticator.generateSecret();
      await createUser({
        username: 'otheruser',
        email: 'other@example.com',
        password: 'OtherPassword123!',
        role: 'user',
        totpSecret: otherTotpSecret,
        backupCodes: ['other-backup']
      });

      const otherAgent = await loginUser('otheruser', 'OtherPassword123!', otherTotpSecret);

      const res = await otherAgent.post(`/api/user/apps/${containerId}/start`);

      expect(res.status).toBe(403);
    });
  });

  describe('POST /api/user/apps/:id/stop', () => {
    it('should stop a running container', async () => {
      // Create and start container
      const createRes = await userAgent
        .post('/api/user/apps')
        .send({
          appType: 'web-terminal',
          subdomain: 'stop-test'
        });

      const containerId = createRes.body.container.id;

      await userAgent.post(`/api/user/apps/${containerId}/start`);

      // Stop it
      const res = await userAgent.post(`/api/user/apps/${containerId}/stop`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe('DELETE /api/user/apps/:id', () => {
    it('should delete a container', async () => {
      // Create container
      const createRes = await userAgent
        .post('/api/user/apps')
        .send({
          appType: 'web-terminal',
          subdomain: 'delete-test'
        });

      const containerId = createRes.body.container.id;

      // Delete it
      const res = await userAgent.delete(`/api/user/apps/${containerId}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should return 404 for non-existent container', async () => {
      const res = await userAgent.delete('/api/user/apps/99999');

      expect(res.status).toBe(404);
    });
  });

  describe('GET /api/user/apps/:id/status', () => {
    it('should return container status', async () => {
      // Create container
      const createRes = await userAgent
        .post('/api/user/apps')
        .send({
          appType: 'web-terminal',
          subdomain: 'status-test'
        });

      const containerId = createRes.body.container.id;

      const res = await userAgent.get(`/api/user/apps/${containerId}/status`);

      expect(res.status).toBe(200);
      expect(res.body.status).toBeDefined();
    });
  });

  describe('Admin Container Routes', () => {
    describe('GET /api/admin/containers', () => {
      it('should return all containers for admin', async () => {
        // Create a container as regular user
        await userAgent
          .post('/api/user/apps')
          .send({
            appType: 'web-terminal',
            subdomain: 'admin-view-test'
          });

        const res = await adminAgent.get('/api/admin/containers');

        expect(res.status).toBe(200);
        expect(res.body.containers).toBeDefined();
        expect(res.body.containers.length).toBeGreaterThanOrEqual(1);
      });

      it('should return 403 for non-admin user', async () => {
        const res = await userAgent.get('/api/admin/containers');

        expect(res.status).toBe(403);
      });
    });

    describe('GET /api/admin/app-types', () => {
      it('should return all app types for admin', async () => {
        const res = await adminAgent.get('/api/admin/app-types');

        expect(res.status).toBe(200);
        expect(res.body.appTypes).toBeDefined();
        expect(res.body.appTypes).toContainEqual(
          expect.objectContaining({ name: 'web-terminal' })
        );
      });
    });

    describe('POST /api/admin/app-types', () => {
      it('should create a new app type', async () => {
        const res = await adminAgent
          .post('/api/admin/app-types')
          .send({
            name: 'jupyter',
            displayName: 'Jupyter Notebook',
            dockerImage: 'jupyter/minimal-notebook:latest',
            defaultPort: 8888,
            description: 'Jupyter Notebook environment'
          });

        expect(res.status).toBe(201);
        expect(res.body.appType).toBeDefined();
        expect(res.body.appType.name).toBe('jupyter');
      });

      it('should return 400 for duplicate app type', async () => {
        const res = await adminAgent
          .post('/api/admin/app-types')
          .send({
            name: 'web-terminal',
            displayName: 'Another Terminal',
            dockerImage: 'some-image:latest',
            defaultPort: 8000
          });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/exists/i);
      });
    });
  });
});
