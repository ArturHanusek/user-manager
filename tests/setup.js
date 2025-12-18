/**
 * Global test setup for Vitest
 * Handles database isolation and cleanup
 */

import { beforeEach, afterAll } from 'vitest';
import { closeDb, resetDb, initDb } from '../lib/db.js';

// Use in-memory database for tests
process.env.NODE_ENV = 'test';
process.env.DB_PATH = ':memory:';
process.env.SESSION_SECRET = 'test-secret-key-for-testing';

// Initialize database once at the start
initDb();

// Reset database before each test for isolation
beforeEach(async () => {
  await resetDb();
});

// Clean up after all tests
afterAll(async () => {
  await closeDb();
});
