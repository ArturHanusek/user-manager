import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.js'],
    exclude: ['tests/e2e/**'],
    setupFiles: ['tests/setup.js'],
    // Run tests sequentially to avoid database conflicts
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true
      }
    },
    sequence: {
      shuffle: false
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['lib/**/*.js', 'server.js'],
      exclude: ['tests/**', 'node_modules/**']
    },
    testTimeout: 10000,
    hookTimeout: 10000
  }
});
