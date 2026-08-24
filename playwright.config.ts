import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './apps/web/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:3000',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: [
    {
      command: 'uv run uvicorn apps.api.main:app --host 0.0.0.0 --port 8000',
      url: 'http://127.0.0.1:8000/ready',
      timeout: 120000,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: 'npm run dev -- --host 0.0.0.0 --port 3000',
      url: 'http://127.0.0.1:3000',
      timeout: 120000,
      reuseExistingServer: !process.env.CI,
    },
  ],
});
