/**
 * Docker Management Module
 * Handles container lifecycle operations
 */

import Docker from 'dockerode';
import { getDb } from './db.js';
import { getUserById } from './auth.js';

const DOCKER_SOCKET = process.env.DOCKER_SOCKET || '/var/run/docker.sock';
const DEFAULT_CPU_LIMIT = process.env.DEFAULT_CPU_LIMIT || '0.5';
const DEFAULT_MEMORY_LIMIT = process.env.DEFAULT_MEMORY_LIMIT || '512m';
const CONTAINER_NETWORK = process.env.CONTAINER_NETWORK || 'user-apps-net';

let docker = null;

/**
 * Initialize Docker client
 */
export function initDocker() {
  docker = new Docker({ socketPath: DOCKER_SOCKET });
  return docker;
}

/**
 * Get Docker client instance
 */
export function getDocker() {
  if (!docker) {
    initDocker();
  }
  return docker;
}

/**
 * Get app type configuration from database
 */
function getAppType(appType) {
  const db = getDb();
  return db.prepare('SELECT * FROM app_types WHERE name = ?').get(appType);
}

/**
 * Create a new container for a user
 * @param {Object} options - Container options
 * @param {number} options.userId - User ID
 * @param {string} options.appType - Application type (e.g., 'web-terminal')
 * @param {string} options.subdomain - Unique subdomain for the container
 * @param {string} [options.cpuLimit] - CPU limit (default: 0.5)
 * @param {string} [options.memoryLimit] - Memory limit (default: 512m)
 * @returns {Promise<Object>} Created container info
 */
export async function createContainer(options) {
  const { userId, appType, subdomain, cpuLimit, memoryLimit } = options;
  const db = getDb();

  // Validate user exists
  const user = getUserById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  // Validate app type exists
  const appConfig = getAppType(appType);
  if (!appConfig) {
    throw new Error('App type not found');
  }

  // Check for duplicate subdomain
  const existingSubdomain = db.prepare('SELECT id FROM containers WHERE subdomain = ?').get(subdomain);
  if (existingSubdomain) {
    throw new Error('Subdomain already exists');
  }

  // Generate container name
  const containerName = `${user.username}-${appType}-${subdomain}`.toLowerCase().replace(/[^a-z0-9-]/g, '-');

  // Find available port (simple approach: use database auto-increment + base port)
  const basePort = appConfig.default_port || 10000;
  const lastContainer = db.prepare('SELECT MAX(port) as maxPort FROM containers').get();
  const port = lastContainer?.maxPort ? lastContainer.maxPort + 1 : basePort;

  // Parse memory limit to bytes for Docker
  const memoryBytes = parseMemoryLimit(memoryLimit || DEFAULT_MEMORY_LIMIT);
  const cpuPeriod = 100000;
  const cpuQuota = Math.floor(parseFloat(cpuLimit || DEFAULT_CPU_LIMIT) * cpuPeriod);

  // Create Docker container
  const dockerClient = getDocker();
  const dockerContainer = await dockerClient.createContainer({
    Image: appConfig.docker_image,
    name: containerName,
    Hostname: subdomain,
    ExposedPorts: {
      [`${appConfig.default_port}/tcp`]: {}
    },
    HostConfig: {
      PortBindings: {
        [`${appConfig.default_port}/tcp`]: [{ HostPort: String(port) }]
      },
      Memory: memoryBytes,
      CpuPeriod: cpuPeriod,
      CpuQuota: cpuQuota,
      NetworkMode: CONTAINER_NETWORK,
      RestartPolicy: { Name: 'unless-stopped' }
    },
    Labels: {
      'user-manager.user-id': String(userId),
      'user-manager.app-type': appType,
      'user-manager.subdomain': subdomain
    }
  });

  // Store container info in database
  const result = db.prepare(`
    INSERT INTO containers (user_id, app_type, container_id, container_name, status, port, subdomain, cpu_limit, memory_limit, created_at)
    VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
  `).run(
    userId,
    appType,
    dockerContainer.id,
    containerName,
    port,
    subdomain,
    cpuLimit || DEFAULT_CPU_LIMIT,
    memoryLimit || DEFAULT_MEMORY_LIMIT,
    Math.floor(Date.now() / 1000)
  );

  return {
    id: result.lastInsertRowid,
    containerId: dockerContainer.id,
    containerName,
    port,
    subdomain,
    status: 'pending'
  };
}

/**
 * Start a container
 * @param {number} containerId - Database container ID
 * @returns {Promise<Object>} Result
 */
export async function startContainer(containerId) {
  const db = getDb();

  // Get container from database
  const container = db.prepare('SELECT * FROM containers WHERE id = ?').get(containerId);
  if (!container) {
    throw new Error('Container not found');
  }

  // Start Docker container
  const dockerClient = getDocker();
  const dockerContainer = dockerClient.getContainer(container.container_id);
  await dockerContainer.start();

  // Update status in database
  db.prepare('UPDATE containers SET status = ? WHERE id = ?').run('running', containerId);

  return { success: true, status: 'running' };
}

/**
 * Stop a container
 * @param {number} containerId - Database container ID
 * @returns {Promise<Object>} Result
 */
export async function stopContainer(containerId) {
  const db = getDb();

  // Get container from database
  const container = db.prepare('SELECT * FROM containers WHERE id = ?').get(containerId);
  if (!container) {
    throw new Error('Container not found');
  }

  // Stop Docker container
  const dockerClient = getDocker();
  const dockerContainer = dockerClient.getContainer(container.container_id);
  await dockerContainer.stop();

  // Update status in database
  db.prepare('UPDATE containers SET status = ? WHERE id = ?').run('stopped', containerId);

  return { success: true, status: 'stopped' };
}

/**
 * Remove a container
 * @param {number} containerId - Database container ID
 * @returns {Promise<Object>} Result
 */
export async function removeContainer(containerId) {
  const db = getDb();

  // Get container from database
  const container = db.prepare('SELECT * FROM containers WHERE id = ?').get(containerId);
  if (!container) {
    throw new Error('Container not found');
  }

  // Get Docker container
  const dockerClient = getDocker();
  const dockerContainer = dockerClient.getContainer(container.container_id);

  // Try to stop if running
  try {
    const info = await dockerContainer.inspect();
    if (info.State.Running) {
      await dockerContainer.stop();
    }
  } catch (e) {
    // Ignore errors when stopping (might already be stopped)
  }

  // Remove Docker container
  await dockerContainer.remove();

  // Remove from database
  db.prepare('DELETE FROM containers WHERE id = ?').run(containerId);

  return { success: true };
}

/**
 * Get container status
 * @param {number} containerId - Database container ID
 * @returns {Promise<Object>} Container status
 */
export async function getContainerStatus(containerId) {
  const db = getDb();

  // Get container from database
  const container = db.prepare('SELECT * FROM containers WHERE id = ?').get(containerId);
  if (!container) {
    throw new Error('Container not found');
  }

  // Get Docker container status
  let dockerStatus = null;
  try {
    const dockerClient = getDocker();
    const dockerContainer = dockerClient.getContainer(container.container_id);
    const info = await dockerContainer.inspect();
    dockerStatus = {
      running: info.State.Running,
      status: info.State.Status,
      startedAt: info.State.StartedAt,
      finishedAt: info.State.FinishedAt
    };
  } catch (e) {
    dockerStatus = { error: e.message };
  }

  return {
    id: container.id,
    userId: container.user_id,
    appType: container.app_type,
    containerName: container.container_name,
    status: container.status,
    port: container.port,
    subdomain: container.subdomain,
    dockerStatus
  };
}

/**
 * List all containers for a user
 * @param {number} userId - User ID
 * @returns {Promise<Array>} List of containers
 */
export async function listUserContainers(userId) {
  const db = getDb();
  const containers = db.prepare('SELECT * FROM containers WHERE user_id = ?').all(userId);
  return containers;
}

/**
 * Get container logs
 * @param {number} containerId - Database container ID
 * @param {Object} [options] - Log options
 * @param {number} [options.tail] - Number of lines to return
 * @returns {Promise<string>} Container logs
 */
export async function getContainerLogs(containerId, options = {}) {
  const db = getDb();

  // Get container from database
  const container = db.prepare('SELECT * FROM containers WHERE id = ?').get(containerId);
  if (!container) {
    throw new Error('Container not found');
  }

  // Get Docker container logs
  const dockerClient = getDocker();
  const dockerContainer = dockerClient.getContainer(container.container_id);

  const logOptions = {
    stdout: true,
    stderr: true,
    tail: options.tail || 1000
  };

  const logs = await dockerContainer.logs(logOptions);
  return logs.toString();
}

/**
 * Parse memory limit string to bytes
 * @param {string} limit - Memory limit (e.g., '512m', '1g')
 * @returns {number} Memory in bytes
 */
function parseMemoryLimit(limit) {
  const match = limit.match(/^(\d+(?:\.\d+)?)\s*([kmg]?)b?$/i);
  if (!match) {
    return 512 * 1024 * 1024; // Default 512MB
  }

  const value = parseFloat(match[1]);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case 'k':
      return value * 1024;
    case 'm':
      return value * 1024 * 1024;
    case 'g':
      return value * 1024 * 1024 * 1024;
    default:
      return value;
  }
}
