/**
 * Database module - SQLite with better-sqlite3
 * Handles all database operations for user management platform
 */

import Database from 'better-sqlite3';

const DB_PATH = process.env.DB_PATH || './data/manager.db';

let db = null;

/**
 * Initialize and return database instance
 */
export function getDb() {
  if (!db) {
    initDb();
  }
  return db;
}

/**
 * Initialize database with schema
 */
export function initDb() {
  db = new Database(DB_PATH);

  // Enable WAL mode for better concurrency
  db.pragma('journal_mode = WAL');

  // Enable foreign key enforcement
  db.pragma('foreign_keys = ON');

  // Create users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      totp_secret TEXT,
      backup_codes TEXT,
      role TEXT DEFAULT 'user',
      email_verified INTEGER DEFAULT 0,
      failed_attempts INTEGER DEFAULT 0,
      locked_until INTEGER,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      updated_at INTEGER DEFAULT (strftime('%s', 'now'))
    )
  `);

  // Create containers table
  db.exec(`
    CREATE TABLE IF NOT EXISTS containers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      app_type TEXT NOT NULL,
      container_id TEXT,
      container_name TEXT UNIQUE,
      status TEXT DEFAULT 'pending',
      port INTEGER,
      subdomain TEXT UNIQUE,
      cpu_limit TEXT DEFAULT '0.5',
      memory_limit TEXT DEFAULT '512m',
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Create app_types table (registry of available apps)
  db.exec(`
    CREATE TABLE IF NOT EXISTS app_types (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      display_name TEXT,
      docker_image TEXT NOT NULL,
      default_port INTEGER,
      description TEXT,
      enabled INTEGER DEFAULT 1
    )
  `);

  // Create api_keys table (for app-to-platform authentication)
  db.exec(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_type TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      last_used INTEGER
    )
  `);

  // Create sessions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      expires_at INTEGER NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Create indexes for performance
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_containers_user ON containers(user_id);
    CREATE INDEX IF NOT EXISTS idx_containers_status ON containers(status);
  `);

  return db;
}

/**
 * Close database connection
 */
export async function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Reset database (for testing) - clears all data and resets sequences
 */
export async function resetDb() {
  if (!db) {
    initDb();
  }

  // Clear all tables in reverse order of dependencies
  db.exec('DELETE FROM sessions');
  db.exec('DELETE FROM containers');
  db.exec('DELETE FROM api_keys');
  db.exec('DELETE FROM app_types');
  db.exec('DELETE FROM users');

  // Reset autoincrement sequences
  db.exec("DELETE FROM sqlite_sequence WHERE name IN ('users', 'containers', 'app_types', 'api_keys')");
}
