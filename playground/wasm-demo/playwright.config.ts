import { defineConfig } from "playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 10 * 60 * 1000,
  expect: { timeout: 30_000 },
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:4173",
    browserName: "chromium",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "node scripts/serve.mjs",
    env: { PORT: "4173" },
    url: "http://127.0.0.1:4173/e2e.html",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
