/**
 * Database module tests (TDD - Red/Green/Refactor)
 * These tests define the expected behavior of the database layer
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  getDb,
  initDb,
  closeDb,
  resetDb
} from '../../../lib/db.js';

describe('Database Module', () => {
  describe('initDb()', () => {
    it('should create and return a database instance', () => {
      const db = getDb();
      expect(db).toBeDefined();
      expect(typeof db.prepare).toBe('function');
    });

    it('should create users table with correct schema', () => {
      const db = getDb();
      const tableInfo = db.prepare("PRAGMA table_info(users)").all();

      const columns = tableInfo.map(col => col.name);
      expect(columns).toContain('id');
      expect(columns).toContain('username');
      expect(columns).toContain('email');
      expect(columns).toContain('password_hash');
      expect(columns).toContain('totp_secret');
      expect(columns).toContain('backup_codes');
      expect(columns).toContain('role');
      expect(columns).toContain('email_verified');
      expect(columns).toContain('failed_attempts');
      expect(columns).toContain('locked_until');
      expect(columns).toContain('created_at');
      expect(columns).toContain('updated_at');
    });

    it('should create containers table with correct schema', () => {
      const db = getDb();
      const tableInfo = db.prepare("PRAGMA table_info(containers)").all();

      const columns = tableInfo.map(col => col.name);
      expect(columns).toContain('id');
      expect(columns).toContain('user_id');
      expect(columns).toContain('app_type');
      expect(columns).toContain('container_id');
      expect(columns).toContain('container_name');
      expect(columns).toContain('status');
      expect(columns).toContain('port');
      expect(columns).toContain('subdomain');
      expect(columns).toContain('cpu_limit');
      expect(columns).toContain('memory_limit');
      expect(columns).toContain('created_at');
    });

    it('should create app_types table with correct schema', () => {
      const db = getDb();
      const tableInfo = db.prepare("PRAGMA table_info(app_types)").all();

      const columns = tableInfo.map(col => col.name);
      expect(columns).toContain('id');
      expect(columns).toContain('name');
      expect(columns).toContain('display_name');
      expect(columns).toContain('docker_image');
      expect(columns).toContain('default_port');
      expect(columns).toContain('description');
      expect(columns).toContain('enabled');
    });

    it('should create api_keys table with correct schema', () => {
      const db = getDb();
      const tableInfo = db.prepare("PRAGMA table_info(api_keys)").all();

      const columns = tableInfo.map(col => col.name);
      expect(columns).toContain('id');
      expect(columns).toContain('app_type');
      expect(columns).toContain('key_hash');
      expect(columns).toContain('created_at');
      expect(columns).toContain('last_used');
    });

    it('should create sessions table with correct schema', () => {
      const db = getDb();
      const tableInfo = db.prepare("PRAGMA table_info(sessions)").all();

      const columns = tableInfo.map(col => col.name);
      expect(columns).toContain('id');
      expect(columns).toContain('user_id');
      expect(columns).toContain('created_at');
      expect(columns).toContain('expires_at');
      expect(columns).toContain('ip_address');
      expect(columns).toContain('user_agent');
    });

    it('should enforce unique constraint on username', () => {
      const db = getDb();

      db.prepare(`
        INSERT INTO users (username, email, password_hash)
        VALUES ('testuser', 'test@test.com', 'hash123')
      `).run();

      expect(() => {
        db.prepare(`
          INSERT INTO users (username, email, password_hash)
          VALUES ('testuser', 'other@test.com', 'hash456')
        `).run();
      }).toThrow();
    });

    it('should enforce unique constraint on email', () => {
      const db = getDb();

      db.prepare(`
        INSERT INTO users (username, email, password_hash)
        VALUES ('user1', 'same@test.com', 'hash123')
      `).run();

      expect(() => {
        db.prepare(`
          INSERT INTO users (username, email, password_hash)
          VALUES ('user2', 'same@test.com', 'hash456')
        `).run();
      }).toThrow();
    });

    it('should set default role to user', () => {
      const db = getDb();

      db.prepare(`
        INSERT INTO users (username, email, password_hash)
        VALUES ('testuser', 'test@test.com', 'hash123')
      `).run();

      const user = db.prepare('SELECT role FROM users WHERE username = ?').get('testuser');
      expect(user.role).toBe('user');
    });

    it('should set default container status to pending', () => {
      const db = getDb();

      // First create a user
      db.prepare(`
        INSERT INTO users (username, email, password_hash)
        VALUES ('testuser', 'test@test.com', 'hash123')
      `).run();

      // Then create a container
      db.prepare(`
        INSERT INTO containers (user_id, app_type)
        VALUES (1, 'web-terminal')
      `).run();

      const container = db.prepare('SELECT status FROM containers WHERE user_id = 1').get();
      expect(container.status).toBe('pending');
    });
  });

  describe('resetDb()', () => {
    it('should clear all data from tables', async () => {
      const db = getDb();

      // Insert test data
      db.prepare(`
        INSERT INTO users (username, email, password_hash)
        VALUES ('testuser', 'test@test.com', 'hash123')
      `).run();

      // Reset
      await resetDb();

      // Verify data is cleared
      const users = db.prepare('SELECT COUNT(*) as count FROM users').get();
      expect(users.count).toBe(0);
    });
  });

  describe('closeDb()', () => {
    it('should close database connection without error', async () => {
      await expect(closeDb()).resolves.not.toThrow();
    });
  });
});
