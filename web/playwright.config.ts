import { defineConfig, devices } from '@playwright/test';

/**
 * Browser tests (docs/13 section 1: Playwright end to end): the real SPA in Chromium against the dev mock
 * (web/dev/mock-server.mjs), the same setup used to check screens by hand. The mock keeps state in memory, so the
 * tests run one at a time, in order.
 */
export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : 'list',
  use: { baseURL: 'http://localhost:5173', trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 860 } } }],
  webServer: [
    { command: 'node dev/mock-server.mjs', url: 'http://127.0.0.1:8099/api/v1/ui-config', reuseExistingServer: !process.env.CI, timeout: 30_000 },
    { command: 'bun --bun run dev', url: 'http://localhost:5173/', reuseExistingServer: !process.env.CI, timeout: 60_000 },
  ],
});
