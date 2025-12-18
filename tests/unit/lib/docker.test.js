/**
 * Unit Tests for Docker Management Module (TDD)
 * Tests for container lifecycle management
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock dockerode before importing the module
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

import {
  initDocker,
  createContainer,
  startContainer,
  stopContainer,
  removeContainer,
  getContainerStatus,
  listUserContainers,
  getContainerLogs
} from '../../../lib/docker.js';

import { initDb, resetDb, closeDb, getDb } from '../../../lib/db.js';
import { createUser } from '../../../lib/auth.js';

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

describe('Docker Management Module', () => {
  let testUserId;

  beforeEach(async () => {
    await resetDb();
    // Seed app types
    seedAppTypes();
    // Create a test user for container operations
    testUserId = await createUser({
      username: 'dockeruser',
      email: 'docker@test.com',
      password: 'ValidPassword123!',
      role: 'user',
      totpSecret: 'testsecret',
      backupCodes: ['code1', 'code2']
    });
    initDocker();
  });

  describe('initDocker', () => {
    it('should initialize Docker client', () => {
      expect(() => initDocker()).not.toThrow();
    });

    it('should use socket path from environment', () => {
      process.env.DOCKER_SOCKET = '/custom/docker.sock';
      expect(() => initDocker()).not.toThrow();
      delete process.env.DOCKER_SOCKET;
    });
  });

  describe('createContainer', () => {
    it('should create a container for a user', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'user1-terminal'
      });

      expect(container).toBeDefined();
      expect(container.containerId).toBeDefined();
    });

    it('should store container info in database', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'user1-terminal'
      });

      const db = getDb();
      const stored = db.prepare('SELECT * FROM containers WHERE id = ?').get(container.id);

      expect(stored).toBeDefined();
      expect(stored.user_id).toBe(testUserId);
      expect(stored.app_type).toBe('web-terminal');
      expect(stored.subdomain).toBe('user1-terminal');
    });

    it('should reject duplicate subdomains', async () => {
      await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'unique-subdomain'
      });

      await expect(createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'unique-subdomain'
      })).rejects.toThrow(/subdomain.*exists/i);
    });

    it('should apply resource limits', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'limited-container',
        cpuLimit: '1.0',
        memoryLimit: '1g'
      });

      const db = getDb();
      const stored = db.prepare('SELECT * FROM containers WHERE id = ?').get(container.id);

      expect(stored.cpu_limit).toBe('1.0');
      expect(stored.memory_limit).toBe('1g');
    });

    it('should use default resource limits if not specified', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'default-limits'
      });

      const db = getDb();
      const stored = db.prepare('SELECT * FROM containers WHERE id = ?').get(container.id);

      expect(stored.cpu_limit).toBe('0.5');
      expect(stored.memory_limit).toBe('512m');
    });

    it('should require valid user ID', async () => {
      await expect(createContainer({
        userId: 99999,
        appType: 'web-terminal',
        subdomain: 'invalid-user'
      })).rejects.toThrow(/user.*not found/i);
    });

    it('should require valid app type', async () => {
      await expect(createContainer({
        userId: testUserId,
        appType: 'invalid-app-type',
        subdomain: 'test-subdomain'
      })).rejects.toThrow(/app type.*not found/i);
    });
  });

  describe('startContainer', () => {
    it('should start a stopped container', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'start-test'
      });

      const result = await startContainer(container.id);
      expect(result.success).toBe(true);
    });

    it('should update container status in database', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'status-update'
      });

      await startContainer(container.id);

      const db = getDb();
      const stored = db.prepare('SELECT status FROM containers WHERE id = ?').get(container.id);
      expect(stored.status).toBe('running');
    });

    it('should reject invalid container ID', async () => {
      await expect(startContainer(99999)).rejects.toThrow(/container.*not found/i);
    });
  });

  describe('stopContainer', () => {
    it('should stop a running container', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'stop-test'
      });

      await startContainer(container.id);
      const result = await stopContainer(container.id);

      expect(result.success).toBe(true);
    });

    it('should update container status to stopped', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'stop-status'
      });

      await startContainer(container.id);
      await stopContainer(container.id);

      const db = getDb();
      const stored = db.prepare('SELECT status FROM containers WHERE id = ?').get(container.id);
      expect(stored.status).toBe('stopped');
    });
  });

  describe('removeContainer', () => {
    it('should remove a container', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'remove-test'
      });

      const result = await removeContainer(container.id);
      expect(result.success).toBe(true);
    });

    it('should remove container record from database', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'remove-db'
      });

      await removeContainer(container.id);

      const db = getDb();
      const stored = db.prepare('SELECT * FROM containers WHERE id = ?').get(container.id);
      expect(stored).toBeUndefined();
    });

    it('should stop container before removing if running', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'stop-before-remove'
      });

      await startContainer(container.id);
      const result = await removeContainer(container.id);

      expect(result.success).toBe(true);
    });
  });

  describe('getContainerStatus', () => {
    it('should return container status', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'status-check'
      });

      const status = await getContainerStatus(container.id);

      expect(status).toBeDefined();
      expect(status.id).toBe(container.id);
      expect(status.status).toBeDefined();
    });

    it('should include Docker container details', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'docker-details'
      });

      await startContainer(container.id);
      const status = await getContainerStatus(container.id);

      expect(status.dockerStatus).toBeDefined();
      expect(status.dockerStatus.running).toBe(true);
    });
  });

  describe('listUserContainers', () => {
    it('should list all containers for a user', async () => {
      await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'list-test-1'
      });

      await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'list-test-2'
      });

      const containers = await listUserContainers(testUserId);

      expect(containers).toHaveLength(2);
    });

    it('should return empty array for user with no containers', async () => {
      const containers = await listUserContainers(testUserId);
      expect(containers).toHaveLength(0);
    });

    it('should not return containers from other users', async () => {
      // Create another user
      const otherUserId = await createUser({
        username: 'otheruser',
        email: 'other@test.com',
        password: 'ValidPassword123!',
        role: 'user',
        totpSecret: 'secret2',
        backupCodes: ['code1']
      });

      await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'user1-container'
      });

      await createContainer({
        userId: otherUserId,
        appType: 'web-terminal',
        subdomain: 'user2-container'
      });

      const user1Containers = await listUserContainers(testUserId);
      const user2Containers = await listUserContainers(otherUserId);

      expect(user1Containers).toHaveLength(1);
      expect(user2Containers).toHaveLength(1);
      expect(user1Containers[0].subdomain).toBe('user1-container');
      expect(user2Containers[0].subdomain).toBe('user2-container');
    });
  });

  describe('getContainerLogs', () => {
    it('should return container logs', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'logs-test'
      });

      await startContainer(container.id);
      const logs = await getContainerLogs(container.id);

      expect(logs).toBeDefined();
      expect(typeof logs).toBe('string');
    });

    it('should limit log lines', async () => {
      const container = await createContainer({
        userId: testUserId,
        appType: 'web-terminal',
        subdomain: 'logs-limit'
      });

      await startContainer(container.id);
      const logs = await getContainerLogs(container.id, { tail: 100 });

      expect(logs).toBeDefined();
    });
  });
});
